use std::{collections::HashMap,sync::Arc,time::{Duration,Instant}};
use serde_json::json;
use crate::{control_client::ControlClient,pool::{UpstreamPool,UpstreamState}};

pub fn spawn(pool:UpstreamPool,clients:Arc<HashMap<String,Arc<ControlClient>>>,interval:Duration) {
    tokio::spawn(async move {
        let mut failures:HashMap<String,u32>=HashMap::new();
        let mut ticker=tokio::time::interval(interval);ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for (id,client) in clients.iter() {
                let start=Instant::now();
                match tokio::time::timeout(Duration::from_secs(5),client.call_timeout("session.list",json!({}),Duration::from_secs(4))).await {
                    Ok(Ok(value))=>{
                        let latency=start.elapsed().as_millis() as u64;
                        let sessions=value["sessions"].as_array();
                        let count=sessions.map(|v|v.len()).unwrap_or(0);
                        failures.remove(id);
                        pool.mark(id,if latency>1_000||sessions.is_none(){UpstreamState::Degraded}else{UpstreamState::Online},Some(latency),count).await;
                    }
                    _=>{let n=failures.entry(id.clone()).or_default();*n+=1;pool.mark(id,if *n>=2{UpstreamState::Offline}else{UpstreamState::Degraded},None,0).await;}
                }
            }
        }
    });
}
