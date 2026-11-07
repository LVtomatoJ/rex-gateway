//! Per-agent event subscriptions.
//!
//! Every agent shares one upstream control connection per upstream, and Rex subscriptions on a
//! connection are additive. Each agent connection therefore keeps its own view of what it asked
//! for, and the event loop only forwards an upstream event to agents that subscribed to it.

use std::{collections::HashMap, sync::{Arc, Mutex}};

use serde_json::Value;

use crate::control_client::{SubscriptionEffect, Subscriptions};

/// Gateway-wide count of agent connections holding an explicit per-session attach, keyed by
/// `(upstream, raw session id)`. `session.detach` only reaches Rex when no other agent holds
/// that session, because Rex would otherwise stop sending its events to everyone.
#[derive(Clone, Default)]
pub struct HoldRegistry { inner: Arc<Mutex<HashMap<(String, String), usize>>> }

impl HoldRegistry {
    fn acquire(&self, upstream: &str, session: &str) {
        *self.inner.lock().expect("holds").entry((upstream.to_owned(), session.to_owned())).or_default() += 1;
    }
    /// Returns how many holders remain.
    fn release(&self, upstream: &str, session: &str) -> usize {
        let mut guard = self.inner.lock().expect("holds");
        let key = (upstream.to_owned(), session.to_owned());
        let Some(count) = guard.get_mut(&key) else { return 0 };
        *count = count.saturating_sub(1);
        let left = *count;
        if left == 0 { guard.remove(&key); }
        left
    }
    pub fn holders(&self, upstream: &str, session: &str) -> usize {
        self.inner.lock().expect("holds").get(&(upstream.to_owned(), session.to_owned())).copied().unwrap_or(0)
    }
}

/// How to roll back an optimistic [`AgentSubscriptions::begin`] when the upstream call fails.
#[derive(Debug, Default)]
pub struct Undo { upstream: String, new_session: Option<String>, set_all: bool, set_all_sessions: bool }

pub struct AgentSubscriptions { per_upstream: Mutex<HashMap<String, Subscriptions>>, holds: HoldRegistry }

impl AgentSubscriptions {
    pub fn new(holds: HoldRegistry) -> Arc<Self> {
        Arc::new(Self { per_upstream: Mutex::new(HashMap::new()), holds })
    }

    /// Apply before the upstream call: Rex can send the first events of a new attach ahead of
    /// its response, and those must not be filtered out for the agent that asked.
    pub fn begin(&self, upstream: &str, effect: &SubscriptionEffect) -> Undo {
        let mut guard = self.per_upstream.lock().expect("subscriptions");
        let subs = guard.entry(upstream.to_owned()).or_default();
        let mut undo = Undo { upstream: upstream.to_owned(), ..Undo::default() };
        match effect {
            SubscriptionEffect::Attach { session, all } => {
                if subs.sessions.insert(session.clone()) {
                    self.holds.acquire(upstream, session);
                    undo.new_session = Some(session.clone());
                }
                if *all && !subs.all { subs.all = true; undo.set_all = true; }
            }
            SubscriptionEffect::BootstrapDefault { all } | SubscriptionEffect::AttachAll { all } if *all => {
                if !subs.all { subs.all = true; undo.set_all = true; }
            }
            SubscriptionEffect::AttachAll { .. } => {
                if !subs.all_sessions { subs.all_sessions = true; undo.set_all_sessions = true; }
            }
            SubscriptionEffect::BootstrapDefault { .. } | SubscriptionEffect::Detach { .. } => {}
        }
        undo
    }

    pub fn undo(&self, undo: Undo) {
        let mut guard = self.per_upstream.lock().expect("subscriptions");
        let Some(subs) = guard.get_mut(&undo.upstream) else { return };
        if let Some(session) = undo.new_session {
            if subs.sessions.remove(&session) { self.holds.release(&undo.upstream, &session); }
        }
        if undo.set_all { subs.all = false; }
        if undo.set_all_sessions { subs.all_sessions = false; }
    }

    /// Record the session Rex picked for a session-less `session.bootstrap`.
    pub fn record_attach(&self, upstream: &str, session: &str) {
        let mut guard = self.per_upstream.lock().expect("subscriptions");
        if guard.entry(upstream.to_owned()).or_default().sessions.insert(session.to_owned()) {
            self.holds.acquire(upstream, session);
        }
    }

    /// Drop this agent's explicit attach. Returns whether the detach should reach Rex (no other
    /// agent connection still holds that session).
    pub fn detach(&self, upstream: &str, session: &str) -> bool {
        let mine = self.per_upstream.lock().expect("subscriptions")
            .get_mut(upstream).is_some_and(|subs| subs.sessions.remove(session));
        let left = if mine { self.holds.release(upstream, session) } else { self.holds.holders(upstream, session) };
        left == 0
    }

    pub fn has_any(&self, upstream: &str) -> bool {
        self.per_upstream.lock().expect("subscriptions").get(upstream).is_some_and(|subs| !subs.is_empty())
    }

    /// Whether an upstream event payload (raw Rex ids) matches this agent's subscriptions:
    /// scope `all` takes everything; otherwise the event's session must be attached
    /// (or covered by `attach_all` with scope `session`). Events without a session id only
    /// go to `all` subscribers.
    pub fn wants(&self, upstream: &str, payload: &Value) -> bool {
        let guard = self.per_upstream.lock().expect("subscriptions");
        let Some(subs) = guard.get(upstream) else { return false };
        if subs.all { return true; }
        match event_session_id(payload) {
            Some(session) => subs.all_sessions || subs.sessions.contains(session),
            None => false,
        }
    }
}

impl Drop for AgentSubscriptions {
    fn drop(&mut self) {
        let guard = self.per_upstream.get_mut().unwrap_or_else(|e| e.into_inner());
        for (upstream, subs) in guard.iter() {
            for session in &subs.sessions { self.holds.release(upstream, session); }
        }
    }
}

/// The session an event is about: the shallowest `session_id` string (an object's own field
/// wins over nested ones). Rex `session_event` frames carry it at `payload.session_id`.
pub fn event_session_id(value: &Value) -> Option<&str> {
    let mut level = vec![value];
    while !level.is_empty() {
        let mut next = Vec::new();
        for value in level {
            match value {
                Value::Object(object) => {
                    if let Some(id) = object.get("session_id").and_then(Value::as_str) { return Some(id); }
                    next.extend(object.values());
                }
                Value::Array(items) => next.extend(items.iter()),
                _ => {}
            }
        }
        level = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn attach(session: &str, all: bool) -> SubscriptionEffect { SubscriptionEffect::Attach { session: session.into(), all } }

    #[test]
    fn filters_by_scope_and_session() {
        let holds = HoldRegistry::default();
        let agent = AgentSubscriptions::new(holds.clone());
        let a = json!({"type":"session_event","payload":{"session_id":"session:a","event":{"type":"x"}}});
        let b = json!({"type":"session_event","payload":{"session_id":"session:b"}});
        let global = json!({"type":"client_joined","payload":{"client_id":"client:1"}});
        assert!(!agent.wants("up", &a), "nothing subscribed");
        agent.begin("up", &attach("session:a", false));
        assert!(agent.wants("up", &a));
        assert!(!agent.wants("up", &b));
        assert!(!agent.wants("up", &global));
        assert!(!agent.wants("other", &a), "per upstream");
        agent.begin("up", &SubscriptionEffect::AttachAll { all: false });
        assert!(agent.wants("up", &b));
        assert!(!agent.wants("up", &global));
        agent.begin("up", &SubscriptionEffect::AttachAll { all: true });
        assert!(agent.wants("up", &global));
        assert!(agent.has_any("up") && !agent.has_any("other"));
    }

    #[test]
    fn undo_reverts_only_what_begin_added() {
        let holds = HoldRegistry::default();
        let agent = AgentSubscriptions::new(holds.clone());
        let a = json!({"session_id":"session:a"});
        agent.begin("up", &attach("session:a", false));
        let again = agent.begin("up", &attach("session:a", true));
        agent.undo(again);
        assert!(agent.wants("up", &a), "earlier attach survives a failed re-attach");
        assert!(!agent.wants("up", &json!({"type":"global"})), "failed all scope rolled back");
        assert_eq!(holds.holders("up", "session:a"), 1);
        let failed = agent.begin("up", &attach("session:b", false));
        agent.undo(failed);
        assert_eq!(holds.holders("up", "session:b"), 0);
    }

    #[test]
    fn detach_forwards_only_when_last_holder_leaves_and_drop_releases() {
        let holds = HoldRegistry::default();
        let x = AgentSubscriptions::new(holds.clone());
        let y = AgentSubscriptions::new(holds.clone());
        x.begin("up", &attach("session:a", false));
        y.begin("up", &attach("session:a", false));
        assert!(!x.detach("up", "session:a"), "y still holds it");
        assert!(!x.wants("up", &json!({"session_id":"session:a"})));
        assert!(y.wants("up", &json!({"session_id":"session:a"})));
        assert!(!x.detach("up", "session:a"), "x no longer holds it, y does");
        drop(y);
        assert_eq!(holds.holders("up", "session:a"), 0);
        assert!(x.detach("up", "session:a"), "nobody holds it any more");
    }

    #[test]
    fn event_session_id_prefers_shallow_field() {
        assert_eq!(event_session_id(&json!({"payload":{"session_id":"session:outer","view":{"session_id":"session:inner"}}})), Some("session:outer"));
        assert_eq!(event_session_id(&json!({"view":{"session_id":"session:v"},"session_id":"session:top"})), Some("session:top"));
        assert_eq!(event_session_id(&json!({"type":"client_joined"})), None);
    }
}
