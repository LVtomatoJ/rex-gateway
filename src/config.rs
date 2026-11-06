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
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig { pub id: String, pub url: String }

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig { pub tokens: Vec<TokenConfig> }

#[derive(Debug, Clone, Deserialize)]
pub struct TokenConfig { pub token: String, pub allow: Vec<String> }

fn default_listen() -> SocketAddr { "127.0.0.1:7300".parse().unwrap() }
fn default_probe() -> u64 { 10_000 }

impl Config {
    pub fn load() -> Result<Self> {
        let path = env::var("REX_GATEWAY_CONFIG").unwrap_or_else(|_| "rex-gateway.toml".to_owned());
        let text = std::fs::read_to_string(PathBuf::from(&path)).with_context(|| format!("reading {path}"))?;
        let mut config: Config = toml::from_str(&text)?;
        if let Ok(listen) = env::var("REX_GATEWAY_LISTEN") { config.listen = listen.parse()?; }
        if let Ok(interval) = env::var("REX_GATEWAY_PROBE_INTERVAL_MS") { config.probe_interval_ms = interval.parse()?; }
        if let Ok(url) = env::var("REX_GATEWAY_UPSTREAM_LOCAL_URL") {
            if let Some(upstream) = config.upstreams.iter_mut().find(|u| u.id == "local") { upstream.url = url; }
        }
        if config.upstreams.is_empty() || config.probe_interval_ms == 0 { bail!("at least one upstream and a nonzero probe interval are required"); }
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
