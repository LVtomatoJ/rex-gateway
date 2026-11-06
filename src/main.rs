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
mod sessions;

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
    let auth = Arc::new(auth::Authenticator::from_entries(config.auth_entries()?));
    let pool = UpstreamPool::new();
    let (events, _) = tokio::sync::broadcast::channel(1024);
    let mut clients: HashMap<String, Arc<ControlClient>> = HashMap::new();
    let call_timeout = Duration::from_millis(config.upstream_call_timeout_ms);
    for item in &config.upstreams {
        // Upstreams start Unknown and never block startup: the control client connects lazily
        // and the probe loop promotes (or demotes) them.
        pool.upsert_with_metadata(&item.id, &item.url, Source::Manual, item.tags.clone(), item.description.clone()).await;
        clients.insert(item.id.clone(), Arc::new(ControlClient::new(item.id.clone(), item.url.clone(), control_client::Options { call_timeout, ping_interval: Duration::from_millis(config.ws_ping_interval_ms), idle_timeout: Duration::from_millis(config.ws_idle_timeout_ms) }, events.clone())));
    }
    probe::spawn(pool.clone(), Arc::new(clients.clone()), Duration::from_millis(config.probe_interval_ms));
    let metrics = metrics::Metrics::new();
    let tickets = data::TicketMap::new(Duration::from_millis(config.ticket_ttl_ms), config.ticket_max, metrics.clone());
    tickets.spawn_reaper();
    let sessions = sessions::SessionStore::open(&config.session_store_path, Duration::from_millis(config.session_ttl_ms), config.session_max)?;
    sessions.spawn_reaper();
    let options = inbound::Options { data_connect_timeout: Duration::from_millis(config.data_connect_timeout_ms), ping_interval: Duration::from_millis(config.ws_ping_interval_ms), idle_timeout: Duration::from_millis(config.ws_idle_timeout_ms), max_data_streams: config.max_data_streams, max_data_streams_per_token: config.max_data_streams_per_token, create_reservation_ttl: Duration::from_millis(config.create_reservation_ttl_ms) };
    inbound::serve(config.listen, pool, clients, auth, tickets, sessions, metrics, options, events).await
}
