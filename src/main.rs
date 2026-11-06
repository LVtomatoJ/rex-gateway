mod auth;
mod config;
mod control_client;
mod data;
mod inbound;
mod pool;
mod probe;
mod protocol;

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
    let auth = Arc::new(config.auth_map()?);
    let pool = UpstreamPool::new();
    let mut clients: HashMap<String, Arc<ControlClient>> = HashMap::new();
    for item in &config.upstreams {
        pool.upsert(&item.id, &item.url, Source::Manual).await;
        let client = ControlClient::connect(item.url.clone()).await?;
        clients.insert(item.id.clone(), Arc::new(client));
    }
    probe::spawn(pool.clone(), Arc::new(clients.clone()), Duration::from_millis(config.probe_interval_ms));
    let tickets = data::TicketMap::new();
    inbound::serve(config.listen, pool, clients, auth, tickets).await
}
