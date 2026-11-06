mod auth;
mod config;
mod control_client;
mod data;
mod inbound;
mod metrics;
mod pool;
mod probe;
mod protocol;
mod status;

use std::{collections::HashMap, sync::Arc, time::Duration};
use anyhow::Result;
use config::Config;
use control_client::ControlClient;
use pool::{Source, UpstreamPool};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let config = Config::load()?;
    let auth = Arc::new(auth::Authenticator::new(config.auth_map()?));
    let pool = UpstreamPool::new();
    let mut clients: HashMap<String, Arc<ControlClient>> = HashMap::new();
    let call_timeout = Duration::from_millis(config.upstream_call_timeout_ms);
    for item in &config.upstreams {
        // Upstreams start Unknown and never block startup: the control client connects lazily
        // and the probe loop promotes (or demotes) them.
        pool.upsert(&item.id, &item.url, Source::Manual).await;
        clients.insert(item.id.clone(), Arc::new(ControlClient::new(item.url.clone(), call_timeout)));
    }
    probe::spawn(pool.clone(), Arc::new(clients.clone()), Duration::from_millis(config.probe_interval_ms));
    let metrics = metrics::Metrics::new();
    let tickets = data::TicketMap::new(Duration::from_millis(config.ticket_ttl_ms), config.ticket_max, metrics.clone());
    tickets.spawn_reaper();
    let options = inbound::Options { data_connect_timeout: Duration::from_millis(config.data_connect_timeout_ms) };
    inbound::serve(config.listen, pool, clients, auth, tickets, metrics, options).await
}
