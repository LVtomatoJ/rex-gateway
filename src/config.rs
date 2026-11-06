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
fn default_call_timeout() -> u64 { 10_000 }
fn default_data_connect_timeout() -> u64 { 10_000 }
fn default_ping_interval() -> u64 { 20_000 }
fn default_idle_timeout() -> u64 { 120_000 }

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
        if let Some(url) = env("REX_GATEWAY_UPSTREAM_LOCAL_URL") {
            if let Some(upstream) = config.upstreams.iter_mut().find(|u| u.id == "local") { upstream.url = url; }
        }
        if config.upstreams.is_empty() || config.probe_interval_ms == 0 { bail!("at least one upstream and a nonzero probe interval are required"); }
        if config.ticket_ttl_ms == 0 || config.ticket_max == 0 || config.ws_ping_interval_ms == 0 || config.ws_idle_timeout_ms == 0 { bail!("ticket_ttl_ms, ticket_max, ws_ping_interval_ms and ws_idle_timeout_ms must be nonzero"); }
        if config.ws_idle_timeout_ms <= config.ws_ping_interval_ms { bail!("ws_idle_timeout_ms must exceed ws_ping_interval_ms"); }
        if config.upstream_call_timeout_ms == 0 || config.data_connect_timeout_ms == 0 {
            bail!("upstream_call_timeout_ms and data_connect_timeout_ms must be nonzero");
        }
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
