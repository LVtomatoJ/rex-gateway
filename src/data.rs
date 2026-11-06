use std::{collections::HashMap, sync::Arc};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub upstream: String,
    pub upstream_ticket: String,
    owner: String,
}

/// Single-use, bearer-bound mapping from gateway tickets to upstream tickets.
#[derive(Clone, Default)]
pub struct TicketMap(Arc<Mutex<HashMap<String, Ticket>>>);

impl TicketMap {
    pub fn new() -> Self { Self::default() }

    pub async fn insert(&self, upstream: &str, upstream_ticket: &str, owner: &str) -> String {
        let external = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
        self.0.lock().await.insert(external.clone(), Ticket {
            upstream: upstream.to_owned(), upstream_ticket: upstream_ticket.to_owned(), owner: owner.to_owned(),
        });
        external
    }

    pub async fn take(&self, external: &str, owner: &str) -> Option<Ticket> {
        let mut tickets = self.0.lock().await;
        if tickets.get(external)?.owner != owner { return None; }
        tickets.remove(external)
    }
}

pub fn decode_hello(bytes: &[u8]) -> Option<String> {
    let ticket = bytes.strip_prefix(&[1])?;
    (ticket.len() == 16).then(|| URL_SAFE_NO_PAD.encode(ticket))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ticket_routes_once_and_checks_owner() {
        let map = TicketMap::new();
        let external = map.insert("local", "real-ticket", "secret").await;
        assert_eq!(map.take(&external, "other").await, None);
        assert_eq!(map.take(&external, "secret").await, Some(Ticket {
            upstream: "local".into(), upstream_ticket: "real-ticket".into(), owner: "secret".into(),
        }));
        assert_eq!(map.take(&external, "secret").await, None);
    }

    #[test]
    fn decodes_binary_hello() {
        let raw = [7u8; 16];
        assert_eq!(decode_hello(&[&[1][..], &raw].concat()).unwrap(), URL_SAFE_NO_PAD.encode(raw));
        assert_eq!(decode_hello(&raw), None);
        assert_eq!(decode_hello(&[1, 2]), None);
    }
}
