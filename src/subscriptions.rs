//! Per-agent event subscriptions.
//!
//! Every agent shares one upstream control connection per upstream, and Rex subscriptions on a
//! connection are additive. Each agent connection therefore keeps its own view of what it asked
//! for, and the event loop only forwards an upstream event to agents that subscribed to it.

use std::{collections::HashMap, sync::{Arc, Mutex}};

use serde_json::{json, Value};

use crate::control_client::{ClientMap, ControlClient, ReplayFilter, SubscriptionEffect, Subscriptions};

/// Gateway-wide count of agent connections holding an explicit per-session attach, keyed by
/// `(upstream, raw session id)`, plus per-upstream counts of agents holding scope `all` /
/// `attach_all` `session`. `session.detach` only reaches Rex when no other agent holds that
/// session, because Rex would otherwise stop sending its events to everyone. When an agent
/// connection closes, sessions it was the last holder of are detached upstream.
#[derive(Clone, Default)]
pub struct HoldRegistry {
    inner: Arc<Mutex<HashMap<(String, String), usize>>>,
    scopes: Arc<Mutex<HashMap<String, ScopeHolds>>>,
    /// Where to send the upstream detach when the last holder closes. `None` in unit tests.
    clients: Option<ClientMap>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ScopeHolds { all: usize, all_sessions: usize }

#[derive(Clone, Copy)]
enum Scope { All, AllSessions }

impl HoldRegistry {
    pub fn new(clients: ClientMap) -> Self { Self { clients: Some(clients), ..Self::default() } }
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
    fn scope(&self, upstream: &str, scope: Scope, acquire: bool) {
        let mut guard = self.scopes.lock().expect("scopes");
        let holds = guard.entry(upstream.to_owned()).or_default();
        let count = match scope { Scope::All => &mut holds.all, Scope::AllSessions => &mut holds.all_sessions };
        *count = if acquire { *count + 1 } else { count.saturating_sub(1) };
        if *holds == ScopeHolds::default() { guard.remove(upstream); }
    }
    /// `(all, attach_all session)` holder counts on one upstream.
    #[cfg(test)]
    pub fn scope_holders(&self, upstream: &str) -> (usize, usize) {
        self.scopes.lock().expect("scopes").get(upstream).map_or((0, 0), |h| (h.all, h.all_sessions))
    }

    /// Replay filter for an upstream control client: after a reconnect, re-subscribe only
    /// what some agent connection still holds. Rex has no call that undoes `attach_all` or
    /// scope `all`, so a reconnect is the only point where stale ones can be dropped.
    pub fn replay_filter(&self) -> ReplayFilter {
        let (inner, scopes) = (self.inner.clone(), self.scopes.clone());
        Arc::new(move |upstream: &str, subs: &mut Subscriptions| {
            let held = scopes.lock().expect("scopes").get(upstream).copied().unwrap_or_default();
            subs.all &= held.all > 0;
            subs.all_sessions &= held.all_sessions > 0;
            let sessions = inner.lock().expect("holds");
            subs.sessions.retain(|session| sessions.contains_key(&(upstream.to_owned(), session.clone())));
        })
    }

    /// Let `client` prune its replay set against these holds (idempotent).
    pub fn watch(&self, client: &ControlClient) { client.set_replay_filter(self.replay_filter()); }

    /// Detach `session` on Rex in the background (the last holder's connection closed).
    fn detach_upstream(&self, upstream: &str, session: &str) {
        let Some(client) = self.clients.as_ref().and_then(|clients| clients.get(upstream)) else { return };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let (holds, upstream, session) = (self.clone(), upstream.to_owned(), session.to_owned());
        runtime.spawn(async move {
            match client.call("session.detach", json!({"session_id": session})).await {
                Ok(reply) if !reply.is_application_error() => holds.reattach_if_held(&client, &upstream, &session).await,
                Ok(_) | Err(_) => tracing::debug!(%upstream, %session, "upstream detach after agent close failed"),
            }
        });
    }

    /// A forwarded `session.detach` raced an attach from another agent connection: put the
    /// session back on the shared upstream socket (Rex attach is idempotent).
    pub async fn reattach_if_held(&self, client: &ControlClient, upstream: &str, session: &str) {
        if self.holders(upstream, session) == 0 { return; }
        if let Err(error) = client.call("session.attach", json!({"session_id": session, "event_scope": "session"})).await {
            tracing::warn!(%upstream, %session, %error, "re-attach after racing detach failed");
        }
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
                if *all && !subs.all { subs.all = true; undo.set_all = true; self.holds.scope(upstream, Scope::All, true); }
            }
            SubscriptionEffect::BootstrapDefault { all } | SubscriptionEffect::AttachAll { all } if *all => {
                if !subs.all { subs.all = true; undo.set_all = true; self.holds.scope(upstream, Scope::All, true); }
            }
            SubscriptionEffect::AttachAll { .. } => {
                if !subs.all_sessions { subs.all_sessions = true; undo.set_all_sessions = true; self.holds.scope(upstream, Scope::AllSessions, true); }
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
        if undo.set_all { subs.all = false; self.holds.scope(&undo.upstream, Scope::All, false); }
        if undo.set_all_sessions { subs.all_sessions = false; self.holds.scope(&undo.upstream, Scope::AllSessions, false); }
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
        // Runs once the connection loop and every in-flight RPC task are done with it.
        for (upstream, subs) in guard.iter() {
            for session in &subs.sessions {
                if self.holds.release(upstream, session) == 0 { self.holds.detach_upstream(upstream, session); }
            }
            if subs.all { self.holds.scope(upstream, Scope::All, false); }
            if subs.all_sessions { self.holds.scope(upstream, Scope::AllSessions, false); }
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
    fn scope_holds_follow_begin_undo_drop_and_prune_replay() {
        let holds = HoldRegistry::default();
        let x = AgentSubscriptions::new(holds.clone());
        let y = AgentSubscriptions::new(holds.clone());
        x.begin("up", &SubscriptionEffect::AttachAll { all: true });
        x.begin("up", &SubscriptionEffect::AttachAll { all: true });
        y.begin("up", &SubscriptionEffect::AttachAll { all: false });
        let failed = y.begin("up", &attach("session:a", true));
        assert_eq!(holds.scope_holders("up"), (2, 1));
        y.undo(failed);
        assert_eq!(holds.scope_holders("up"), (1, 1));
        y.begin("up", &attach("session:b", false));
        let recorded = || Subscriptions { all: true, all_sessions: true, sessions: ["session:a".to_owned(), "session:b".to_owned()].into() };
        let filter = holds.replay_filter();
        let mut subs = recorded();
        filter("up", &mut subs);
        assert_eq!(subs, Subscriptions { all: true, all_sessions: true, sessions: ["session:b".to_owned()].into() });
        drop(x);
        let mut subs = recorded();
        filter("up", &mut subs);
        assert_eq!(subs, Subscriptions { all: false, all_sessions: true, sessions: ["session:b".to_owned()].into() }, "all no longer held");
        drop(y);
        assert_eq!(holds.scope_holders("up"), (0, 0));
        let mut subs = recorded();
        filter("up", &mut subs);
        assert!(subs.is_empty(), "nothing held: nothing replayed");
    }

    #[test]
    fn event_session_id_prefers_shallow_field() {
        assert_eq!(event_session_id(&json!({"payload":{"session_id":"session:outer","view":{"session_id":"session:inner"}}})), Some("session:outer"));
        assert_eq!(event_session_id(&json!({"view":{"session_id":"session:v"},"session_id":"session:top"})), Some("session:top"));
        assert_eq!(event_session_id(&json!({"type":"client_joined"})), None);
    }
}
