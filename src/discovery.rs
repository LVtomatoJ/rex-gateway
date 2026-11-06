//! Fill the upstream pool from a `rex-discover --json` file (and optional restart snapshot).
//!
//! Reconciliation rule: discovered (non-Manual) upstreams that disappear from the file are
//! **removed when idle** (no remembered session references). If sessions still point at them
//! they stay in the pool (sticky) so attach/list/RPC keep working, but `accept_creates` is
//! cleared so new `session.create` will not pick them. Manual upstreams are never overwritten
//! or deleted by discovery.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Deserialize;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::{
    control_client::{ClientMap, ControlClient, Options, UpstreamEvent},
    pool::{Source, UpstreamPool},
    sessions::SessionStore,
};

#[derive(Debug, Clone, Deserialize)]
struct DiscoverEntry {
    #[serde(default)]
    source: String,
    name: String,
    addr: String,
    #[serde(default)]
    mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUpstream {
    pub id: String,
    pub url: String,
    pub source: Source,
}

/// Sanitize a discover `name` into a stable upstream id (filesystem / id safe).
pub fn sanitize_id(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for c in name.chars() {
        let ok = c.is_ascii_alphanumeric() || c == '-' || c == '_';
        let ch = if ok { c.to_ascii_lowercase() } else { '-' };
        if ch == '-' {
            if prev_dash || out.is_empty() { continue; }
            prev_dash = true;
            out.push('-');
        } else {
            prev_dash = false;
            out.push(ch);
        }
    }
    while out.ends_with('-') { out.pop(); }
    if out.is_empty() { "discovered".into() } else { out }
}

fn normalize_url(addr: &str) -> Option<String> {
    let trimmed = addr.trim();
    if trimmed.is_empty() { return None; }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Some(trimmed.to_owned());
    }
    // rex-discover usually emits a scheme; if missing, default to https.
    Some(format!("https://{trimmed}"))
}

fn parse_source(raw: &str) -> Source {
    if raw.eq_ignore_ascii_case("tailnet") { Source::Tailnet } else { Source::Lan }
}

/// Parse a rex-discover `--json` array (also used for the restart snapshot).
pub fn parse_discover_json(text: &str) -> Result<Vec<ParsedUpstream>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("discovery JSON: {e}"))?;
    let arr = value.as_array().ok_or_else(|| "discovery JSON must be an array".to_owned())?;
    let mut out = Vec::new();
    for item in arr {
        let entry: DiscoverEntry = serde_json::from_value(item.clone())
            .map_err(|e| format!("discovery entry: {e}"))?;
        let id = sanitize_id(&entry.name);
        let Some(url) = normalize_url(&entry.addr) else { continue };
        let source = parse_source(&entry.source);
        out.push(ParsedUpstream { id, url, source });
        let _ = entry.mode; // retained for forward-compat with rex-discover output
    }
    Ok(out)
}

fn read_path(path: &Path) -> Result<Vec<ParsedUpstream>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_discover_json(&text)
}

fn write_store_atomic(path: &Path, entries: &[ParsedUpstream]) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let arr: Vec<Value> = entries.iter().map(|e| {
        serde_json::json!({
            "source": match e.source { Source::Tailnet => "tailnet", Source::Lan => "lan", Source::Manual => "manual" },
            "name": e.id,
            "addr": e.url,
            "mode": "",
        })
    }).collect();
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        serde_json::to_writer_pretty(&mut f, &arr).map_err(|e| format!("write store: {e}"))?;
        f.write_all(b"\n").map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| format!("rename store: {e}"))?;
    Ok(())
}

/// Apply a parsed discovery snapshot to the pool/clients.
///
/// - Upserts Tailnet/Lan entries (Unknown until probed); never overwrites Manual.
/// - Creates a ControlClient for newly seen ids (or recreates when the URL changes).
/// - Removes idle discovered ids absent from `entries`; sticky (has session refs) stay with
///   `accept_creates = false`.
pub async fn apply(
    pool: &UpstreamPool,
    clients: &ClientMap,
    sessions: Option<&SessionStore>,
    entries: &[ParsedUpstream],
    client_options: Options,
    events: broadcast::Sender<UpstreamEvent>,
) {
    let desired: std::collections::HashSet<String> = entries.iter().map(|e| e.id.clone()).collect();
    for entry in entries {
        if pool.is_manual(&entry.id).await {
            tracing::debug!(id = %entry.id, "discovery skipped Manual id collision");
            continue;
        }
        let url_changed = match pool.get(&entry.id).await {
            Some(existing) => existing.url != entry.url,
            None => true,
        };
        pool.upsert_with_metadata(&entry.id, &entry.url, entry.source, Vec::new(), None).await;
        if url_changed || !clients.contains(&entry.id) {
            let client = Arc::new(ControlClient::new(
                entry.id.clone(), entry.url.clone(), client_options, events.clone(),
            ));
            clients.insert(entry.id.clone(), client);
        }
    }
    for id in pool.discovered_ids().await {
        if desired.contains(&id) { continue; }
        let sticky = sessions.map(|s| s.has_upstream(&id)).unwrap_or(false);
        if sticky {
            pool.set_accept_creates(&id, false).await;
            tracing::info!(%id, "discovery: host gone but sticky sessions remain; create disabled");
        } else {
            pool.remove_discovered(&id).await;
            clients.remove(&id);
            tracing::info!(%id, "discovery: removed idle discovered upstream");
        }
    }
}

/// Load optional restart snapshot (ignore missing file).
pub async fn load_store_if_present(
    path: &Path,
    pool: &UpstreamPool,
    clients: &ClientMap,
    sessions: Option<&SessionStore>,
    client_options: Options,
    events: broadcast::Sender<UpstreamEvent>,
) {
    match read_path(path) {
        Ok(entries) => {
            tracing::info!(path = %path.display(), n = entries.len(), "loaded discovery store");
            apply(pool, clients, sessions, &entries, client_options, events).await;
        }
        Err(e) if path.exists() => tracing::warn!(%e, "discovery store unreadable"),
        Err(_) => {}
    }
}

/// Background loop: re-read `file` every `interval`, apply, optionally persist `store_path`.
pub fn spawn(
    file: PathBuf,
    interval: Duration,
    store_path: Option<PathBuf>,
    pool: UpstreamPool,
    clients: ClientMap,
    sessions: SessionStore,
    client_options: Options,
    events: broadcast::Sender<UpstreamEvent>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match read_path(&file) {
                Ok(entries) => {
                    apply(&pool, &clients, Some(&sessions), &entries, client_options, events.clone()).await;
                    if let Some(ref store) = store_path {
                        if let Err(e) = write_store_atomic(store, &entries) {
                            tracing::warn!(%e, "could not persist discovery store");
                        }
                    }
                }
                Err(e) if file.exists() => tracing::warn!(%e, "discovery file unreadable"),
                Err(_) => {} // file not yet present — wait for the next interval
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::UpstreamState;
    use tempfile::tempdir;

    #[test]
    fn sanitize_and_parse_json() {
        assert_eq!(sanitize_id("Omarchy-Rex"), "omarchy-rex");
        assert_eq!(sanitize_id("a..b::c"), "a-b-c");
        assert_eq!(sanitize_id("***"), "discovered");
        let parsed = parse_discover_json(r#"[
            {"source":"tailnet","name":"omarchy-rex","addr":"https://omarchy-rex.tail.ts.net","mode":"builtin-443"},
            {"source":"LAN","name":"lan-42","addr":"192.168.1.42:7297","mode":"7297"}
        ]"#).unwrap();
        assert_eq!(parsed[0], ParsedUpstream { id: "omarchy-rex".into(), url: "https://omarchy-rex.tail.ts.net".into(), source: Source::Tailnet });
        assert_eq!(parsed[1].source, Source::Lan);
        assert_eq!(parsed[1].url, "https://192.168.1.42:7297");
    }

    #[tokio::test]
    async fn apply_adds_updates_drops_and_protects_manual() {
        let dir = tempdir().unwrap();
        let pool = UpstreamPool::new();
        let clients = ClientMap::new();
        let sessions = SessionStore::open(dir.path().join("sessions.json"), Duration::from_secs(60), 16).unwrap();
        let (events, _) = broadcast::channel(8);
        let opts = Options { call_timeout: Duration::from_millis(50), ping_interval: Duration::from_secs(10), idle_timeout: Duration::from_secs(30) };

        pool.upsert_with_metadata("local", "http://127.0.0.1:7297", Source::Manual, vec![], None).await;
        clients.insert("local".into(), Arc::new(ControlClient::new("local".into(), "http://127.0.0.1:7297".into(), opts, events.clone())));

        let file = dir.path().join("discovered.json");
        fs::write(&file, r#"[
            {"source":"tailnet","name":"box-a","addr":"http://10.0.0.1:7297","mode":"7297"},
            {"source":"lan","name":"box-b","addr":"http://10.0.0.2:7297","mode":"7297"},
            {"source":"tailnet","name":"local","addr":"http://should-not-win:1","mode":"7297"}
        ]"#).unwrap();
        let entries = read_path(&file).unwrap();
        apply(&pool, &clients, Some(&sessions), &entries, opts, events.clone()).await;

        assert_eq!(pool.get("local").await.unwrap().url, "http://127.0.0.1:7297");
        assert_eq!(pool.get("local").await.unwrap().source, Source::Manual);
        assert_eq!(pool.get("box-a").await.unwrap().source, Source::Tailnet);
        assert_eq!(pool.get("box-b").await.unwrap().source, Source::Lan);
        assert_eq!(pool.get("box-a").await.unwrap().state, UpstreamState::Unknown);
        assert!(clients.contains("box-a") && clients.contains("box-b"));

        // Update URL for box-a
        let entries = parse_discover_json(r#"[{"source":"tailnet","name":"box-a","addr":"http://10.0.0.9:7297","mode":"7297"},{"source":"lan","name":"box-b","addr":"http://10.0.0.2:7297","mode":"7297"}]"#).unwrap();
        apply(&pool, &clients, Some(&sessions), &entries, opts, events.clone()).await;
        assert_eq!(pool.get("box-a").await.unwrap().url, "http://10.0.0.9:7297");

        // Drop box-b while idle → removed
        let entries = parse_discover_json(r#"[{"source":"tailnet","name":"box-a","addr":"http://10.0.0.9:7297","mode":"7297"}]"#).unwrap();
        apply(&pool, &clients, Some(&sessions), &entries, opts, events.clone()).await;
        assert!(pool.get("box-b").await.is_none());
        assert!(!clients.contains("box-b"));

        // Sticky: record a session on box-a, drop it from file → kept, create disabled
        sessions.record("box-a", "session:sticky");
        let entries = parse_discover_json(r#"[]"#).unwrap();
        apply(&pool, &clients, Some(&sessions), &entries, opts, events.clone()).await;
        let sticky = pool.get("box-a").await.unwrap();
        assert!(!sticky.accept_creates);
        assert!(clients.contains("box-a"));

        // Persist store round-trip
        let store = dir.path().join("store.json");
        let entries = parse_discover_json(r#"[{"source":"lan","name":"again","addr":"http://1.2.3.4:9","mode":"7297"}]"#).unwrap();
        write_store_atomic(&store, &entries).unwrap();
        let reloaded = read_path(&store).unwrap();
        assert_eq!(reloaded[0].id, "again");
        assert_eq!(reloaded[0].source, Source::Lan);
    }
}
