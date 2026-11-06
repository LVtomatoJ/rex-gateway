use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf};
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig { pub id: String, pub url: String }

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig { pub tokens: Vec<TokenConfig> }

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig { pub token: String, pub allow: Vec<String> }

fn default_listen() -> SocketAddr { "127.0.0.1:7300".parse().unwrap() }
fn default_probe() -> u64 { 10_000 }
fn default_ticket_ttl() -> u64 { 30_000 }
fn default_ticket_max() -> usize { 1024 }

impl Config {
    pub fn load() -> Result<Self> {
        let path = env::var("REX_GATEWAY_CONFIG").unwrap_or_else(|_| "rex-gateway.toml".to_owned());
        let text = std::fs::read_to_string(PathBuf::from(&path)).with_context(|| format!("reading {path}"))?;
        let mut config: Config = toml::from_str(&text)?;
        if let Ok(listen) = env::var("REX_GATEWAY_LISTEN") { config.listen = listen.parse()?; }
        if let Ok(interval) = env::var("REX_GATEWAY_PROBE_INTERVAL_MS") { config.probe_interval_ms = interval.parse()?; }
        if let Ok(ttl) = env::var("REX_GATEWAY_TICKET_TTL_MS") { config.ticket_ttl_ms = ttl.parse()?; }
        if let Ok(max) = env::var("REX_GATEWAY_TICKET_MAX") { config.ticket_max = max.parse()?; }
        if let Ok(url) = env::var("REX_GATEWAY_UPSTREAM_LOCAL_URL") {
            if let Some(upstream) = config.upstreams.iter_mut().find(|u| u.id == "local") { upstream.url = url; }
        }
        if config.upstreams.is_empty() || config.probe_interval_ms == 0 { bail!("at least one upstream and a nonzero probe interval are required"); }
        if config.ticket_ttl_ms == 0 || config.ticket_max == 0 { bail!("ticket_ttl_ms and ticket_max must be nonzero"); }
        config.auth_map()?;
        Ok(config)
    }

    pub fn auth_map(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut result = HashMap::new();
        for item in &self.auth.tokens {
            if item.token.is_empty() || item.allow.is_empty() { bail!("tokens and allow lists must be nonempty"); }
            if result.insert(item.token.clone(), item.allow.clone()).is_some() { bail!("duplicate auth token"); }
        }
        if result.is_empty() { bail!("at least one token is required"); }
        Ok(result)
    }
}

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
