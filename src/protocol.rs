use serde_json::Value;

use crate::{data::TicketMap, sessions::SessionStore};

pub const SUBPROTOCOL: &str = "rex.control.v1";

/// Single source of truth for agent and upstream control+data WebSocket message caps.
/// Advertised in the welcome `limits.max_message_bytes` and matches Rex itself (1 MiB).
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// Stateless session namespace: `<upstream>:<real session:...>`.
/// Already-namespaced ids (any owner) are left unchanged so a second wrap cannot
/// produce `local:local:session:…` and break recording / routing.
pub fn wrap_session_id(upstream: &str, session_id: &str) -> String {
    if unwrap_session_id(session_id).is_some() {
        // Owner already present; never nest another prefix.
        return session_id.to_owned();
    }
    format!("{upstream}:{session_id}")
}

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
///
/// Each rewritten ticket is bound to the nearest enclosing namespaced `session_id`
/// (this object, then parent objects, then `enclosing`). That lets the data plane refuse
/// forgotten/expired session references even when the ticket came from `session.list`,
/// `session.bootstrap`, or an event — not only from a top-level `data.connect`.
pub fn namespace_response(
    value: &mut Value,
    upstream: &str,
    tickets: &TicketMap,
    owner: &str,
    enclosing: Option<&str>,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                namespace_response(item, upstream, tickets, owner, enclosing);
            }
        }
        Value::Object(object) => {
            // Resolve bind target before mutating so ticket order vs session_id order does not matter.
            let local = object
                .get("session_id")
                .and_then(Value::as_str)
                .map(|id| wrap_session_id(upstream, id));
            let bind_to = local.as_deref().or(enclosing);
            for (key, item) in object.iter_mut() {
                if key == "session_id" {
                    if let Some(id) = item.as_str() {
                        *item = Value::String(wrap_session_id(upstream, id));
                    }
                } else if key == "ticket" {
                    if let Some(ticket) = item.as_str() {
                        *item = Value::String(tickets.insert_bound(upstream, ticket, owner, bind_to));
                    }
                } else {
                    namespace_response(item, upstream, tickets, owner, bind_to);
                }
            }
        }
        _ => {}
    }
}

/// Applies an upstream namespace to an event (including events nested in its payload).
/// `default_session` binds tickets in payloads that lack a local `session_id` (e.g. a bare
/// `data.connect` ticket response) to the request's namespaced session reference.
pub fn namespace_and_record(
    value: &mut Value,
    upstream: &str,
    tickets: &TicketMap,
    owner: &str,
    sessions: &SessionStore,
    default_session: Option<&str>,
) {
    namespace_response(value, upstream, tickets, owner, default_session);
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

/// Test helper that namespaces an upstream event payload the same way production does
/// via [`namespace_and_record`] (without recording). Kept for unit coverage of the
/// event frame shape; the live control path builds the frame itself after recording.
#[cfg(test)]
pub fn namespace_event(event: &Value, upstream: &str, seq: u64, tickets: &TicketMap, owner: &str) -> Option<Value> {
    (event.get("type").and_then(Value::as_str) == Some("event")).then(|| {
        let mut payload = event.get("payload").cloned().unwrap_or(Value::Null);
        namespace_response(&mut payload, upstream, tickets, owner, None);
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
        namespace_response(&mut value, "local", &map, "bearer", None);
        assert_eq!(value["session_id"], "local:session:root");
        assert_eq!(value["view"]["session_id"], "local:session:view");
        assert_eq!(value["alternates"][0]["session_id"], "local:session:child");
        assert_eq!(value["text"], "ticket");
        assert_ne!(value["view"]["terminal"]["ticket"], "upstream-a");
        for ticket in [&value["view"]["terminal"]["ticket"], &value["alternates"][0]["ticket"], &value["alternates"][1]["ticket"]] {
            assert_eq!(base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, ticket.as_str().unwrap()).unwrap().len(), 16);
        }
        for (external, expected, bound) in [
            (&value["view"]["terminal"]["ticket"], "upstream-a", "local:session:view"),
            (&value["alternates"][0]["ticket"], "upstream-b", "local:session:child"),
            (&value["alternates"][1]["ticket"], "upstream-c", "local:session:root"),
        ] {
            let mapped = map.take(external.as_str().unwrap(), "bearer").unwrap();
            assert_eq!(mapped.upstream, "local");
            assert_eq!(mapped.upstream_ticket, expected);
            assert_eq!(mapped.session_id.as_deref(), Some(bound), "ticket must bind to nearest session");
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
        assert_eq!(mapped.session_id.as_deref(), Some("local:session:v"));
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

    #[test]
    fn records_sessions_from_namespaced_payload_once() {
        let map = tickets();
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().join("s.json"), std::time::Duration::from_secs(60), 16).unwrap();
        let mut value = json!({
            "session_id":"session:root",
            "view":{"session_id":"session:view","ticket":"up-a"},
            "alternates":[{"session_id":"session:child"}]
        });
        namespace_and_record(&mut value, "local", &map, "bearer", &store, None);
        assert_eq!(value["session_id"], "local:session:root");
        assert_eq!(value["view"]["session_id"], "local:session:view");
        assert_eq!(value["alternates"][0]["session_id"], "local:session:child");
        assert_eq!(map.pending(), 1, "ticket rewritten exactly once");
        assert!(store.contains("local:session:root"));
        assert!(store.contains("local:session:view"));
        assert!(store.contains("local:session:child"));
    }

    #[test]
    fn wrap_session_id_is_idempotent() {
        let once = wrap_session_id("local", "session:e");
        assert_eq!(once, "local:session:e");
        assert_eq!(wrap_session_id("local", &once), once);
        assert_eq!(wrap_session_id("other", &once), once, "never nest a foreign prefix either");
        assert_eq!(unwrap_session_id(&once), Some(("local", "session:e")));
    }

    #[test]
    fn default_session_binds_bare_ticket_responses() {
        let map = tickets();
        let mut value = json!({"ticket":"up-bare","expires_in_ms":1000});
        namespace_response(&mut value, "local", &map, "bearer", Some("local:session:req"));
        let mapped = map.take(value["ticket"].as_str().unwrap(), "bearer").unwrap();
        assert_eq!(mapped.upstream_ticket, "up-bare");
        assert_eq!(mapped.session_id.as_deref(), Some("local:session:req"));
    }

    #[test]
    fn double_namespace_still_reissues_tickets() {
        // Session ids stay stable under a second wrap, but tickets are rewritten again
        // (gateway tickets are indistinguishable from upstream ones). Production must
        // still call namespace_* exactly once per payload.
        let map = tickets();
        let dir = tempfile::tempdir().unwrap();
        let store = SessionStore::open(dir.path().join("s.json"), std::time::Duration::from_secs(60), 16).unwrap();
        let mut value = json!({"session_id":"session:e","ticket":"up-a"});
        namespace_and_record(&mut value, "local", &map, "bearer", &store, None);
        assert_eq!(value["session_id"], "local:session:e");
        assert_eq!(map.pending(), 1);
        assert!(store.contains("local:session:e"));
        let first_ticket = value["ticket"].as_str().unwrap().to_owned();
        namespace_response(&mut value, "local", &map, "bearer", None);
        assert_eq!(value["session_id"], "local:session:e", "session wrap is idempotent");
        assert_eq!(map.pending(), 2, "second ticket rewrite still orphans capacity");
        assert_ne!(value["ticket"].as_str().unwrap(), first_ticket);
    }
}
