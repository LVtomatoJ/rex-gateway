use serde_json::Value;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
