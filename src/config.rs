use std::{env, net::SocketAddr, path::PathBuf};
use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    pub auth: AuthConfig,
    #[serde(default = "default_probe")]
    pub probe_interval_ms: u64,
    /// Lifetime of an unused gateway data ticket.
    #[serde(default = "default_ticket_ttl")]
    pub ticket_ttl_ms: u64,
    /// Maximum number of pending (unused) data tickets; the oldest is evicted when full.
    #[serde(default = "default_ticket_max")]
    pub ticket_max: usize,
    /// Per-call timeout for requests sent to an upstream control connection (also bounds
    /// (re)connecting it), so one hung upstream cannot hang an agent request.
    #[serde(default = "default_call_timeout")]
    pub upstream_call_timeout_ms: u64,
    /// Timeout for reading the agent's data-plane HELLO and for connecting to the upstream data socket.
    #[serde(default = "default_data_connect_timeout")]
    pub data_connect_timeout_ms: u64,
    /// WebSocket keepalive interval for agent and upstream control/data connections.
    #[serde(default = "default_ping_interval")]
    pub ws_ping_interval_ms: u64,
    /// Close a socket when no application traffic arrives for this long (ping/pong do not count).
    #[serde(default = "default_idle_timeout")]
    pub ws_idle_timeout_ms: u64,
    /// Maximum concurrently bridged data streams across the whole gateway.
    #[serde(default = "default_max_data")]
    pub max_data_streams: usize,
    /// Maximum concurrently bridged data streams for one bearer token.
    #[serde(default = "default_max_data_per_token")]
    pub max_data_streams_per_token: usize,
    /// Time an upstream selected for session.create carries one extra reservation.
    #[serde(default = "default_reservation_ttl")]
    pub create_reservation_ttl_ms: u64,
    /// Durable namespace -> upstream session mapping (atomically replaced JSON).
    #[serde(default = "default_session_store")]
    pub session_store_path: PathBuf,
    /// Idle session references are forgotten after this duration.
    #[serde(default = "default_session_ttl")]
    pub session_ttl_ms: u64,
    /// Maximum remembered sessions; the least-recently active are forgotten first.
    #[serde(default = "default_session_max")]
    pub session_max: usize,
    /// Optional rex-discover file watcher and/or live command that fills the upstream pool.
    #[serde(default)]
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub id: String,
    pub url: String,
    #[serde(default)] pub tags: Vec<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig { pub tokens: Vec<TokenConfig> }

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig {
    pub token: String,
    pub allow: Vec<String>,
    #[serde(default)] pub prefer_tags: Vec<String>,
    #[serde(default)] pub avoid_tags: Vec<String>,
    #[serde(default)] pub prefer_hosts: Vec<String>,
    #[serde(default)] pub avoid_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryConfig {
    /// Path to a JSON file in `rex-discover --json` format; re-read on interval when set
    /// and `command` is unset.
    pub file: Option<PathBuf>,
    /// Optional argv for a live discover subprocess (first element = program). When set,
    /// each interval runs this command and applies its stdout JSON; takes precedence over `file`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// How often to refresh discovery (file read or command run).
    #[serde(default = "default_discovery_interval")]
    pub interval_ms: u64,
    /// Optional path to persist the last successfully applied discovery snapshot.
    pub store_path: Option<PathBuf>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            file: None,
            command: None,
            interval_ms: default_discovery_interval(),
            store_path: None,
        }
    }
}

impl DiscoveryConfig {
    /// True when either a nonempty file path or a nonempty command argv is configured.
    pub fn enabled(&self) -> bool {
        self.file.as_ref().is_some_and(|p| !p.as_os_str().is_empty())
            || self.command.as_ref().is_some_and(|c| !c.is_empty())
    }
}

fn default_listen() -> SocketAddr { "127.0.0.1:7300".parse().unwrap() }
fn default_probe() -> u64 { 10_000 }
fn default_ticket_ttl() -> u64 { 30_000 }
fn default_ticket_max() -> usize { 1024 }
fn default_call_timeout() -> u64 { 10_000 }
fn default_data_connect_timeout() -> u64 { 10_000 }
fn default_ping_interval() -> u64 { 20_000 }
fn default_idle_timeout() -> u64 { 120_000 }
fn default_max_data() -> usize { 128 }
fn default_max_data_per_token() -> usize { 32 }
fn default_reservation_ttl() -> u64 { 5_000 }
fn default_session_store() -> PathBuf { PathBuf::from("rex-gateway-sessions.json") }
fn default_session_ttl() -> u64 { 86_400_000 }
fn default_session_max() -> usize { 16_384 }
fn default_discovery_interval() -> u64 { 30_000 }

impl Config {
    pub fn load() -> Result<Self> {
        let path = env::var("REX_GATEWAY_CONFIG").unwrap_or_else(|_| "rex-gateway.toml".to_owned());
        let text = std::fs::read_to_string(PathBuf::from(&path)).with_context(|| format!("reading {path}"))?;
        Self::from_toml(&text, |name| env::var(name).ok())
    }

    /// Parses `text`, applies environment-style overrides from `env` and validates the result.
    pub fn from_toml(text: &str, env: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let mut config: Config = toml::from_str(text)?;
        if let Some(listen) = env("REX_GATEWAY_LISTEN") { config.listen = listen.parse()?; }
        if let Some(v) = env("REX_GATEWAY_PROBE_INTERVAL_MS") { config.probe_interval_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_TICKET_TTL_MS") { config.ticket_ttl_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_TICKET_MAX") { config.ticket_max = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_UPSTREAM_CALL_TIMEOUT_MS") { config.upstream_call_timeout_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_DATA_CONNECT_TIMEOUT_MS") { config.data_connect_timeout_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_WS_PING_INTERVAL_MS") { config.ws_ping_interval_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_WS_IDLE_TIMEOUT_MS") { config.ws_idle_timeout_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_MAX_DATA_STREAMS") { config.max_data_streams = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_MAX_DATA_STREAMS_PER_TOKEN") { config.max_data_streams_per_token = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_CREATE_RESERVATION_TTL_MS") { config.create_reservation_ttl_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_SESSION_STORE_PATH") { config.session_store_path = v.into(); }
        if let Some(v) = env("REX_GATEWAY_SESSION_TTL_MS") { config.session_ttl_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_SESSION_MAX") { config.session_max = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_DISCOVERY_FILE") { config.discovery.file = Some(v.into()); }
        if let Some(v) = env("REX_GATEWAY_DISCOVERY_COMMAND") {
            let argv: Vec<String> = v.split_ascii_whitespace().map(str::to_owned).collect();
            config.discovery.command = if argv.is_empty() { None } else { Some(argv) };
        }
        if let Some(v) = env("REX_GATEWAY_DISCOVERY_INTERVAL_MS") { config.discovery.interval_ms = v.parse()?; }
        if let Some(v) = env("REX_GATEWAY_DISCOVERY_STORE_PATH") { config.discovery.store_path = Some(v.into()); }
        // Per-upstream environment keys use the exact ID: REX_GATEWAY_UPSTREAM_<ID>_{TAGS,DESCRIPTION}.
        // Tags are comma-separated; an unset variable leaves TOML unchanged.
        for (index, token) in config.auth.tokens.iter_mut().enumerate() {
            if let Some(v) = env(&format!("REX_GATEWAY_AUTH_TOKEN_{index}_PREFER_TAGS")) { token.prefer_tags = parse_list(&v); }
            if let Some(v) = env(&format!("REX_GATEWAY_AUTH_TOKEN_{index}_AVOID_TAGS")) { token.avoid_tags = parse_list(&v); }
            if let Some(v) = env(&format!("REX_GATEWAY_AUTH_TOKEN_{index}_PREFER_HOSTS")) { token.prefer_hosts = parse_list(&v); }
            if let Some(v) = env(&format!("REX_GATEWAY_AUTH_TOKEN_{index}_AVOID_HOSTS")) { token.avoid_hosts = parse_list(&v); }
        }
        for upstream in &mut config.upstreams {
            let prefix = format!("REX_GATEWAY_UPSTREAM_{}", upstream.id);
            if let Some(v) = env(&format!("{prefix}_TAGS")) { upstream.tags = parse_list(&v); }
            if let Some(v) = env(&format!("{prefix}_DESCRIPTION")) { upstream.description = Some(v); }
        }
        if let Some(url) = env("REX_GATEWAY_UPSTREAM_LOCAL_URL") {
            if let Some(upstream) = config.upstreams.iter_mut().find(|u| u.id == "local") { upstream.url = url; }
        }
        if let Some(ref cmd) = config.discovery.command {
            if cmd.is_empty() { bail!("discovery.command must be nonempty when set"); }
            if cmd[0].trim().is_empty() { bail!("discovery.command program must be nonempty"); }
        }
        let discovery_enabled = config.discovery.enabled();
        if config.upstreams.is_empty() && !discovery_enabled {
            bail!("at least one upstream is required (or set discovery.file / discovery.command)");
        }
        if config.probe_interval_ms == 0 { bail!("a nonzero probe interval is required"); }
        if discovery_enabled && config.discovery.interval_ms == 0 {
            bail!("discovery.interval_ms must be nonzero when discovery is enabled");
        }
        if config.ticket_ttl_ms == 0 || config.ticket_max == 0 || config.ws_ping_interval_ms == 0 || config.ws_idle_timeout_ms == 0 { bail!("ticket_ttl_ms, ticket_max, ws_ping_interval_ms and ws_idle_timeout_ms must be nonzero"); }
        if config.max_data_streams == 0 || config.max_data_streams_per_token == 0 { bail!("max_data_streams and max_data_streams_per_token must be nonzero"); }
        if config.ws_idle_timeout_ms <= config.ws_ping_interval_ms { bail!("ws_idle_timeout_ms must exceed ws_ping_interval_ms"); }
        if config.upstream_call_timeout_ms == 0 || config.data_connect_timeout_ms == 0 {
            bail!("upstream_call_timeout_ms and data_connect_timeout_ms must be nonzero");
        }
        config.auth_entries()?;
        if config.create_reservation_ttl_ms == 0 { bail!("create_reservation_ttl_ms must be nonzero"); }
        if config.session_ttl_ms == 0 || config.session_max == 0 { bail!("session_ttl_ms and session_max must be nonzero"); }
        if config.session_store_path.as_os_str().is_empty() { bail!("session_store_path must be nonempty"); }
        Ok(config)
    }

    pub fn auth_entries(&self) -> Result<Vec<crate::auth::TokenEntry>> {
        let mut result = Vec::new();
        for item in &self.auth.tokens {
            if item.token.is_empty() || item.allow.is_empty() { bail!("tokens and allow lists must be nonempty"); }
            if result.iter().any(|entry: &crate::auth::TokenEntry| entry.token == item.token) { bail!("duplicate auth token"); }
            result.push(crate::auth::TokenEntry {
                token: item.token.clone(), acl: item.allow.clone(),
                prefer_tags: item.prefer_tags.clone(), avoid_tags: item.avoid_tags.clone(),
                prefer_hosts: item.prefer_hosts.clone(), avoid_hosts: item.avoid_hosts.clone(),
            });
        }
        if result.is_empty() { bail!("at least one token is required"); }
        Ok(result)
    }
}

fn parse_list(value: &str) -> Vec<String> { value.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect() }

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "[[upstreams]]\nid=\"a\"\nurl=\"http://a\"\n[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n";

    #[test]
    fn ticket_settings_have_defaults_and_can_be_set() {
        let config: Config = toml::from_str(BASE).unwrap();
        assert_eq!((config.ticket_ttl_ms, config.ticket_max), (30_000, 1024));
        let config: Config = toml::from_str(&format!("ticket_ttl_ms = 500\nticket_max = 7\n{BASE}")).unwrap();
        assert_eq!((config.ticket_ttl_ms, config.ticket_max), (500, 7));
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    const BASE: &str = "[[upstreams]]\nid=\"local\"\nurl=\"http://a\"\n[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n";
    fn no_env(_: &str) -> Option<String> { None }

    #[test]
    fn timeout_defaults_toml_and_env_overrides() {
        let config = Config::from_toml(BASE, no_env).unwrap();
        assert_eq!((config.upstream_call_timeout_ms, config.data_connect_timeout_ms), (10_000, 10_000));
        let config = Config::from_toml(&format!("upstream_call_timeout_ms = 250\ndata_connect_timeout_ms = 300\n{BASE}"), no_env).unwrap();
        assert_eq!((config.upstream_call_timeout_ms, config.data_connect_timeout_ms), (250, 300));
        let env = |name: &str| match name {
            "REX_GATEWAY_UPSTREAM_CALL_TIMEOUT_MS" => Some("77".to_owned()),
            "REX_GATEWAY_DATA_CONNECT_TIMEOUT_MS" => Some("88".to_owned()),
            "REX_GATEWAY_UPSTREAM_LOCAL_URL" => Some("http://override:1".to_owned()),
            _ => None,
        };
        let config = Config::from_toml(&format!("upstream_call_timeout_ms = 250\n{BASE}"), env).unwrap();
        assert_eq!((config.upstream_call_timeout_ms, config.data_connect_timeout_ms), (77, 88));
        assert_eq!(config.upstreams[0].url, "http://override:1");
    }

    #[test]
    fn zero_timeouts_are_rejected() {
        assert!(Config::from_toml(&format!("upstream_call_timeout_ms = 0\n{BASE}"), no_env).is_err());
        assert!(Config::from_toml(&format!("data_connect_timeout_ms = 0\n{BASE}"), no_env).is_err());
        let env = |name: &str| (name == "REX_GATEWAY_UPSTREAM_CALL_TIMEOUT_MS").then(|| "0".to_owned());
        assert!(Config::from_toml(BASE, env).is_err());
        let env = |name: &str| (name == "REX_GATEWAY_DATA_CONNECT_TIMEOUT_MS").then(|| "0".to_owned());
        assert!(Config::from_toml(BASE, env).is_err());
        let env = |name: &str| (name == "REX_GATEWAY_DATA_CONNECT_TIMEOUT_MS").then(|| "abc".to_owned());
        assert!(Config::from_toml(BASE, env).is_err(), "non-numeric rejected");
    }
}

#[cfg(test)]
mod keepalive_tests {
    use super::*;
    const BASE: &str = "[[upstreams]]\nid=\"a\"\nurl=\"http://a\"\n[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n";
    #[test]
    fn configurable_keepalive_defaults_and_validation() {
        let config = Config::from_toml(BASE, |_| None).unwrap();
        assert_eq!((config.ws_ping_interval_ms, config.ws_idle_timeout_ms), (20_000,120_000));
        let config = Config::from_toml(&format!("ws_ping_interval_ms=1000\nws_idle_timeout_ms=4000\n{BASE}"), |_| None).unwrap();
        assert_eq!((config.ws_ping_interval_ms, config.ws_idle_timeout_ms), (1000,4000));
        assert!(Config::from_toml(&format!("ws_idle_timeout_ms=1000\n{BASE}"), |_| None).is_err());
        assert!(Config::from_toml(BASE, |key| (key == "REX_GATEWAY_WS_IDLE_TIMEOUT_MS").then(|| "1000".into())).is_err());
    }
}

#[cfg(test)]
mod data_limit_tests {
    use super::*;
    const BASE: &str = "[[upstreams]]\nid=\"a\"\nurl=\"http://a\"\n[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n";
    #[test]
    fn max_data_streams_defaults_and_validation() {
        let config = Config::from_toml(BASE, |_| None).unwrap();
        assert_eq!((config.max_data_streams, config.max_data_streams_per_token), (128, 32));
        let config = Config::from_toml(&format!("max_data_streams=4\nmax_data_streams_per_token=2\n{BASE}"), |_| None).unwrap();
        assert_eq!((config.max_data_streams, config.max_data_streams_per_token), (4, 2));
        assert!(Config::from_toml(&format!("max_data_streams=0\n{BASE}"), |_| None).is_err());
        assert!(Config::from_toml(BASE, |k| (k == "REX_GATEWAY_MAX_DATA_STREAMS_PER_TOKEN").then(|| "0".into())).is_err());
    }
}


#[cfg(test)]
mod session_tests {
    use super::*;
    const BASE: &str = "[[upstreams]]\nid=\"a\"\nurl=\"http://a\"\n[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n";
    #[test]
    fn durable_session_defaults_toml_env_and_validation() {
        let c=Config::from_toml(BASE, |_| None).unwrap();
        assert_eq!((c.session_ttl_ms,c.session_max),(86_400_000,16_384));
        assert_eq!(c.session_store_path,PathBuf::from("rex-gateway-sessions.json"));
        let c=Config::from_toml(&format!("session_store_path=\"state/s.json\"\nsession_ttl_ms=99\nsession_max=3\n{BASE}"), |_|None).unwrap();
        assert_eq!((c.session_ttl_ms,c.session_max),(99,3));
        let env=|k:&str|match k { "REX_GATEWAY_SESSION_STORE_PATH"=>Some("x.json".into()),"REX_GATEWAY_SESSION_TTL_MS"=>Some("88".into()),"REX_GATEWAY_SESSION_MAX"=>Some("2".into()),_=>None };
        let c=Config::from_toml(BASE,env).unwrap();
        assert_eq!((c.session_store_path,c.session_ttl_ms,c.session_max),(PathBuf::from("x.json"),88,2));
        assert!(Config::from_toml(&format!("session_ttl_ms=0\n{BASE}"), |_|None).is_err());
        assert!(Config::from_toml(&format!("session_max=0\n{BASE}"), |_|None).is_err());
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    const BASE: &str = r#"[[upstreams]]
id="high-mem"
url="http://a"
tags=["perf","prod-svc"]
description="Heavy compile"
[[auth.tokens]]
token="t"
allow=["*"]
prefer_tags=["perf"]
avoid_tags=["clash"]
"#;
    #[test]
    fn metadata_preferences_and_env_overrides() {
        let c=Config::from_toml(BASE, |_| None).unwrap();
        assert_eq!(c.upstreams[0].tags, ["perf","prod-svc"]);
        assert_eq!(c.upstreams[0].description.as_deref(),Some("Heavy compile"));
        let auth=c.auth_entries().unwrap();
        assert_eq!(auth[0].prefer_tags,["perf"]); assert_eq!(auth[0].avoid_tags,["clash"]);
        assert_eq!(c.create_reservation_ttl_ms,5_000);
        let env=|k:&str| match k {
            "REX_GATEWAY_UPSTREAM_high-mem_TAGS"=>Some("macos, perf".into()),
            "REX_GATEWAY_UPSTREAM_high-mem_DESCRIPTION"=>Some("Mac build host".into()),
            "REX_GATEWAY_CREATE_RESERVATION_TTL_MS"=>Some("250".into()), _=>None
        };
        let c=Config::from_toml(BASE,env).unwrap();
        assert_eq!(c.upstreams[0].tags,["macos","perf"]);
        assert_eq!(c.upstreams[0].description.as_deref(),Some("Mac build host"));
        assert_eq!(c.create_reservation_ttl_ms,250);
        assert!(Config::from_toml("create_reservation_ttl_ms=0\n".to_owned().as_str(), |_| None).is_err());
    }
}

#[cfg(test)]
mod host_and_discovery_tests {
    use super::*;
    const BASE: &str = r#"[[upstreams]]
id="high-mem"
url="http://a"
[[auth.tokens]]
token="t"
allow=["*"]
prefer_hosts=["high-mem"]
avoid_hosts=["clash-box"]
"#;
    #[test]
    fn prefer_avoid_hosts_and_discovery_config() {
        let c=Config::from_toml(BASE, |_| None).unwrap();
        let auth=c.auth_entries().unwrap();
        assert_eq!(auth[0].prefer_hosts,["high-mem"]);
        assert_eq!(auth[0].avoid_hosts,["clash-box"]);
        assert!(c.discovery.file.is_none());
        assert!(c.discovery.command.is_none());
        assert!(!c.discovery.enabled());
        assert_eq!(c.discovery.interval_ms,30_000);
        let toml = format!("[discovery]\nfile=\"discovered.json\"\ninterval_ms=1000\nstore_path=\"snap.json\"\n{BASE}");
        let c=Config::from_toml(&toml, |_| None).unwrap();
        assert_eq!(c.discovery.file.as_deref(), Some(std::path::Path::new("discovered.json")));
        assert_eq!(c.discovery.interval_ms,1000);
        assert_eq!(c.discovery.store_path.as_deref(), Some(std::path::Path::new("snap.json")));
        assert!(c.discovery.enabled());
        let toml = format!("[discovery]\ncommand=[\"rex-discover\",\"--json\",\"--tailnet-only\"]\ninterval_ms=5000\n{BASE}");
        let c=Config::from_toml(&toml, |_| None).unwrap();
        assert_eq!(c.discovery.command.as_deref(), Some(&["rex-discover".into(),"--json".into(),"--tailnet-only".into()][..]));
        assert!(c.discovery.enabled());
        let env=|k:&str| match k {
            "REX_GATEWAY_AUTH_TOKEN_0_PREFER_HOSTS"=>Some("a, b".into()),
            "REX_GATEWAY_AUTH_TOKEN_0_AVOID_HOSTS"=>Some("c".into()),
            "REX_GATEWAY_DISCOVERY_FILE"=>Some("env.json".into()),
            "REX_GATEWAY_DISCOVERY_COMMAND"=>Some("rex-discover --json".into()),
            "REX_GATEWAY_DISCOVERY_INTERVAL_MS"=>Some("500".into()),
            "REX_GATEWAY_DISCOVERY_STORE_PATH"=>Some("env-store.json".into()),
            _=>None
        };
        let c=Config::from_toml(BASE,env).unwrap();
        assert_eq!(c.auth_entries().unwrap()[0].prefer_hosts,["a","b"]);
        assert_eq!(c.auth_entries().unwrap()[0].avoid_hosts,["c"]);
        assert_eq!(c.discovery.file.as_deref(), Some(std::path::Path::new("env.json")));
        assert_eq!(c.discovery.command.as_deref(), Some(&["rex-discover".into(),"--json".into()][..]));
        assert_eq!(c.discovery.interval_ms,500);
        assert_eq!(c.discovery.store_path.as_deref(), Some(std::path::Path::new("env-store.json")));
        let c=Config::from_toml("[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n[discovery]\nfile=\"d.json\"\n", |_| None).unwrap();
        assert!(c.upstreams.is_empty());
        let c=Config::from_toml("[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n[discovery]\ncommand=[\"rex-discover\",\"--json\"]\n", |_| None).unwrap();
        assert!(c.upstreams.is_empty());
        assert!(c.discovery.enabled());
        assert!(Config::from_toml("[[auth.tokens]]\ntoken=\"t\"\nallow=[\"*\"]\n", |_| None).is_err());
        assert!(Config::from_toml(&format!("[discovery]\nfile=\"d.json\"\ninterval_ms=0\n{BASE}"), |_| None).is_err());
        assert!(Config::from_toml(&format!("[discovery]\ncommand=[\"rex-discover\"]\ninterval_ms=0\n{BASE}"), |_| None).is_err());
        assert!(Config::from_toml(&format!("[discovery]\ncommand=[]\n{BASE}"), |_| None).is_err());
        assert!(Config::from_toml(&format!("[discovery]\ncommand=[\"\"]\n{BASE}"), |_| None).is_err());
        let env=|k:&str| (k == "REX_GATEWAY_DISCOVERY_COMMAND").then(|| "   ".into());
        let c=Config::from_toml(BASE,env).unwrap();
        assert!(c.discovery.command.is_none());
    }
}
