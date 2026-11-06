use std::{collections::HashMap,sync::Arc,time::{Duration,Instant}};
use serde_json::json;
use crate::{control_client::ControlClient,pool::{UpstreamPool,UpstreamState}};

pub fn spawn(pool:UpstreamPool,clients:Arc<HashMap<String,Arc<ControlClient>>>,interval:Duration) {
    tokio::spawn(async move {
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
                        let error=sessions.is_none().then(||"session.list reply had no sessions array".to_owned());
                        pool.mark_with_error(id,if latency>1_000||sessions.is_none(){UpstreamState::Degraded}else{UpstreamState::Online},Some(latency),count,error).await;
                    }
                    Ok(Err(error))=>{pool.mark_failure(id,format!("{error:#}")).await;}
                    Err(_)=>{pool.mark_failure(id,"probe timed out".to_owned()).await;}
                }
            }
        }
    });
}
