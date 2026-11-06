mod auth;
mod config;
mod control_client;
mod data;
mod discovery;
mod inbound;
mod metrics;
mod pool;
mod probe;
mod protocol;
mod status;
mod sessions;

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use config::Config;
use control_client::{ClientMap, ControlClient};
use pool::{Source, UpstreamPool};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(EnvFilter::from_default_env()).init();
    let config = Config::load()?;
    let auth = Arc::new(auth::Authenticator::from_entries(config.auth_entries()?));
    let pool = UpstreamPool::new();
    let clients = ClientMap::new();
    let (events, _) = tokio::sync::broadcast::channel(1024);
    let call_timeout = Duration::from_millis(config.upstream_call_timeout_ms);
    let client_options = control_client::Options {
        call_timeout,
        ping_interval: Duration::from_millis(config.ws_ping_interval_ms),
        idle_timeout: Duration::from_millis(config.ws_idle_timeout_ms),
    };
    for item in &config.upstreams {
        // Upstreams start Unknown and never block startup: the control client connects lazily
        // and the probe loop promotes (or demotes) them.
        pool.upsert_with_metadata(&item.id, &item.url, Source::Manual, item.tags.clone(), item.description.clone()).await;
        clients.insert(item.id.clone(), Arc::new(ControlClient::new(item.id.clone(), item.url.clone(), client_options, events.clone())));
    }
    let sessions = sessions::SessionStore::open(&config.session_store_path, Duration::from_millis(config.session_ttl_ms), config.session_max)?;
    // Reload last discovery snapshot before the live refresh (Manual always wins).
    if let Some(ref store) = config.discovery.store_path {
        discovery::load_store_if_present(store, &pool, &clients, Some(&sessions), client_options, events.clone()).await;
    }
    let discovery_health = if config.discovery.enabled() {
        let command = config.discovery.command.clone().filter(|c| !c.is_empty());
        let file = config.discovery.file.clone().filter(|p| !p.as_os_str().is_empty());
        let mode = if command.is_some() { "command" } else { "file" };
        let health = discovery::DiscoveryHealth::enabled(mode);
        discovery::spawn(
            command,
            file,
            Duration::from_millis(config.discovery.interval_ms),
            config.discovery.store_path.clone(),
            pool.clone(),
            clients.clone(),
            sessions.clone(),
            client_options,
            events.clone(),
            health.clone(),
        );
        health
    } else {
        discovery::DiscoveryHealth::disabled()
    };
    probe::spawn(pool.clone(), clients.clone(), Duration::from_millis(config.probe_interval_ms));
    let metrics = metrics::Metrics::new();
    let tickets = data::TicketMap::new(Duration::from_millis(config.ticket_ttl_ms), config.ticket_max, metrics.clone());
    tickets.spawn_reaper();
    sessions.spawn_reaper();
    let options = inbound::Options {
        data_connect_timeout: Duration::from_millis(config.data_connect_timeout_ms),
        ping_interval: Duration::from_millis(config.ws_ping_interval_ms),
        idle_timeout: Duration::from_millis(config.ws_idle_timeout_ms),
        max_data_streams: config.max_data_streams,
        max_data_streams_per_token: config.max_data_streams_per_token,
        create_reservation_ttl: Duration::from_millis(config.create_reservation_ttl_ms),
    };
    inbound::serve(config.listen, pool, clients, auth, tickets, sessions, metrics, options, events, discovery_health).await
}
