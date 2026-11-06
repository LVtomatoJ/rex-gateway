use serde_json::Value;

use crate::{data::TicketMap, sessions::SessionStore};

pub const SUBPROTOCOL: &str = "rex.control.v1";

/// Stateless session namespace: `<upstream>:<real session:...>`.
pub fn wrap_session_id(upstream: &str, session_id: &str) -> String { format!("{upstream}:{session_id}") }

pub fn unwrap_session_id(id: &str) -> Option<(&str, &str)> {
    let (upstream, session_id) = id.split_once(':')?;
    (session_id.starts_with("session:") && !upstream.is_empty()).then_some((upstream, session_id))
}

pub fn translate_session_id(value: &mut Value, upstream: &str, wrap: bool) -> bool {
    let Some(id) = value.get("session_id").and_then(Value::as_str) else { return false };
    let translated = if wrap { wrap_session_id(upstream, id) }
        else if let Some((owner, real)) = unwrap_session_id(id) {
            if owner != upstream { return false; }
            real.to_owned()
        } else { return false };
    value["session_id"] = Value::String(translated);
    true
}

/// Recursively wraps session references and replaces every nested data ticket with a
/// gateway-issued ticket. Only well-known field names are interpreted.
pub fn namespace_response(value: &mut Value, upstream: &str, tickets: &TicketMap, owner: &str) {
    match value {
        Value::Array(items) => for item in items { namespace_response(item, upstream, tickets, owner); },
        Value::Object(object) => {
            for (key, item) in object.iter_mut() {
                if key == "session_id" {
                    if let Some(id) = item.as_str() { *item = Value::String(wrap_session_id(upstream, id)); }
                } else if key == "ticket" {
                    if let Some(ticket) = item.as_str() { *item = Value::String(tickets.insert(upstream, ticket, owner)); }
                } else { namespace_response(item, upstream, tickets, owner); }
            }
        }
        _ => {}
    }
}

/// Applies an upstream namespace to an event (including events nested in its payload).
pub fn namespace_and_record(value: &mut Value, upstream: &str, tickets: &TicketMap, owner: &str, sessions: &SessionStore) {
    namespace_response(value, upstream, tickets, owner);
    fn walk(value: &Value, upstream: &str, sessions: &SessionStore) {
        match value {
            Value::Array(items)=>for item in items{walk(item,upstream,sessions)},
            Value::Object(object)=>for (key,item) in object {
                if key=="session_id" { if let Some(id)=item.as_str(){if let Some((owner,real))=unwrap_session_id(id){if owner==upstream{sessions.record(owner,real);}}} }
                else {walk(item,upstream,sessions)}
            }, _=>{}
        }
    }
    walk(value,upstream,sessions);
}

pub fn namespace_event(event: &Value, upstream: &str, seq: u64, tickets: &TicketMap, owner: &str) -> Option<Value> {
    (event.get("type").and_then(Value::as_str) == Some("event")).then(|| {
        let mut payload = event.get("payload").cloned().unwrap_or(Value::Null);
        namespace_response(&mut payload, upstream, tickets, owner);
        serde_json::json!({"type":"event","seq":seq,"payload":payload})
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tickets() -> TicketMap {
        TicketMap::new(std::time::Duration::from_secs(30), 32, crate::metrics::Metrics::new())
    }

    #[test]
    fn recursively_wraps_sessions_and_all_nested_tickets() {
        let map = tickets();
        let mut value = json!({"session_id":"session:root","view":{"session_id":"session:view","terminal":{"ticket":"upstream-a","expires_in_ms":60000}},"alternates":[{"session_id":"session:child","ticket":"upstream-b"},{"ticket":"upstream-c"}],"text":"ticket"});
        namespace_response(&mut value, "local", &map, "bearer");
        assert_eq!(value["session_id"], "local:session:root");
        assert_eq!(value["view"]["session_id"], "local:session:view");
        assert_eq!(value["alternates"][0]["session_id"], "local:session:child");
        assert_eq!(value["text"], "ticket");
        assert_ne!(value["view"]["terminal"]["ticket"], "upstream-a");
        for ticket in [&value["view"]["terminal"]["ticket"], &value["alternates"][0]["ticket"], &value["alternates"][1]["ticket"]] {
            assert_eq!(base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, ticket.as_str().unwrap()).unwrap().len(), 16);
        }
        for (external, expected) in [(&value["view"]["terminal"]["ticket"], "upstream-a"), (&value["alternates"][0]["ticket"], "upstream-b"), (&value["alternates"][1]["ticket"], "upstream-c")] {
            let mapped = map.take(external.as_str().unwrap(), "bearer").unwrap();
            assert_eq!(mapped.upstream, "local");
            assert_eq!(mapped.upstream_ticket, expected);
        }
    }

    #[test]
    fn event_payload_is_namespaced_recursively() {
        let map = tickets();
        let mut event = namespace_event(&json!({"type":"event","seq":99,"payload":{"session_id":"session:e","view":{"session_id":"session:v","ticket":"real"}}}), "local", 2, &map, "owner").unwrap();
        assert_eq!(event["seq"], 2);
        assert_eq!(event["payload"]["session_id"], "local:session:e");
        assert_eq!(event["payload"]["view"]["session_id"], "local:session:v");
        let mapped = map.take(event["payload"]["view"]["ticket"].as_str().unwrap(), "owner").unwrap();
        assert_eq!(mapped.upstream_ticket, "real");
        event["payload"]["view"]["ticket"] = Value::String("redacted".into());
        assert!(namespace_event(&json!({"type":"response"}), "local", 1, &map, "owner").is_none());
    }

    #[test]
    fn namespace_round_trip() {
        let external = wrap_session_id("local", "session:abc");
        assert_eq!(external, "local:session:abc");
        assert_eq!(unwrap_session_id(&external), Some(("local", "session:abc")));
        assert_eq!(unwrap_session_id("session:abc"), None);
        assert_eq!(unwrap_session_id("local:garbage"), None);
    }

    #[test]
    fn translates_session_payloads() {
        let mut input = json!({"session_id":"local:session:abc"});
        assert!(translate_session_id(&mut input, "local", false));
        assert_eq!(input, json!({"session_id":"session:abc"}));
        assert!(translate_session_id(&mut input, "local", true));
        assert_eq!(input, json!({"session_id":"local:session:abc"}));
    }
}
