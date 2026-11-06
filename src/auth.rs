#[cfg(test)]
use std::collections::HashMap;
use sha2::{Digest, Sha256};

type Digest32 = [u8; 32];

fn digest(bytes: &[u8]) -> Digest32 { Sha256::digest(bytes).into() }

/// Constant-time equality for two byte strings: the running time depends only on the lengths,
/// never on where (or whether) the contents differ.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    for i in 0..a.len().max(b.len()) {
        diff |= u64::from(a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0));
    }
    diff == 0
}

/// Bearer-token authenticator, built once at startup and shared via `Arc`.
///
/// Configured tokens are stored only as SHA-256 digests. A presented token is hashed (so the
/// compared values always have the same length, hiding token length) and compared against
/// *every* configured digest in constant time, with no early exit on the first match.
#[derive(Clone)]
pub struct TokenEntry { pub token: String, pub acl: Vec<String>, pub prefer_tags: Vec<String>, pub avoid_tags: Vec<String> }
#[derive(Clone)]
pub struct Identity { pub acl: Vec<String>, pub prefer_tags: Vec<String>, pub avoid_tags: Vec<String> }
pub struct Authenticator { tokens: Vec<(Digest32, Identity)> }

impl Authenticator {
    #[cfg(test)]
    pub fn new(tokens: HashMap<String, Vec<String>>) -> Self {
        Self::from_entries(tokens.into_iter().map(|(token, acl)| TokenEntry { token, acl, prefer_tags: Vec::new(), avoid_tags: Vec::new() }).collect())
    }
    pub fn from_entries(tokens: Vec<TokenEntry>) -> Self {
        Self { tokens: tokens.into_iter().map(|entry| (digest(entry.token.as_bytes()), Identity { acl: entry.acl, prefer_tags: entry.prefer_tags, avoid_tags: entry.avoid_tags })).collect() }
    }

    pub fn acl(&self, bearer: Option<&str>) -> Option<Vec<String>> {
        let presented = digest(bearer?.strip_prefix("Bearer ")?.as_bytes());
        let mut found: Option<&Vec<String>> = None;
        for (stored, identity) in &self.tokens {
            if ct_eq(stored, &presented) { found = Some(&identity.acl); }
        }
        found.cloned()
    }

    pub fn identify(&self, bearer: Option<&str>) -> Option<Identity> {
        let presented = digest(bearer?.strip_prefix("Bearer ")?.as_bytes());
        let mut found: Option<&Identity> = None;
        for (stored, identity) in &self.tokens { if ct_eq(stored, &presented) { found = Some(identity); } }
        found.cloned()
    }

    pub fn permits(acl: &[String], upstream: &str) -> bool {
        acl.iter().any(|allowed| allowed == "*" || allowed == upstream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acl_filtering_and_authentication() {
        let auth = Authenticator::new(HashMap::from([("secret".into(), vec!["local".into()])]));
        assert_eq!(auth.acl(Some("Bearer secret")), Some(vec!["local".into()]));
        assert_eq!(auth.acl(Some("Bearer wrong")), None);
        assert_eq!(auth.acl(None), None);
        assert!(Authenticator::permits(&["*".into()], "other"));
        assert!(Authenticator::permits(&["local".into()], "local"));
        assert!(!Authenticator::permits(&["local".into()], "other"));
        assert!(!Authenticator::permits(&[], "local"));
    }

    #[test]
    fn bearer_prefix_is_required_and_exact() {
        let auth = Authenticator::new(HashMap::from([("secret".into(), vec!["*".into()])]));
        assert_eq!(auth.acl(Some("secret")), None, "scheme required");
        assert_eq!(auth.acl(Some("bearer secret")), None, "scheme is case sensitive, as before");
        assert_eq!(auth.acl(Some("Bearer  secret")), None);
        assert_eq!(auth.acl(Some("Bearer secret ")), None);
        assert_eq!(auth.acl(Some("Bearer secre")), None, "prefix of a token");
        assert_eq!(auth.acl(Some("Bearer secrets")), None, "token plus suffix");
        assert_eq!(auth.acl(Some("Bearer ")), None, "empty token");
    }

    #[test]
    fn every_configured_token_resolves_to_its_own_acl() {
        let tokens: HashMap<String, Vec<String>> = (0..20).map(|i| (format!("tok-{i}"), vec![format!("up{i}")])).collect();
        let auth = Authenticator::new(tokens);
        for i in 0..20 {
            assert_eq!(auth.acl(Some(&format!("Bearer tok-{i}"))), Some(vec![format!("up{i}")]));
        }
        assert_eq!(auth.acl(Some("Bearer tok-20")), None);
    }

    #[test]
    fn ct_eq_matches_slice_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"), "last byte differs");
        assert!(!ct_eq(b"xbc", b"abc"), "first byte differs");
        assert!(!ct_eq(b"abc", b"ab"), "shorter");
        assert!(!ct_eq(b"ab", b"abc"), "longer");
        assert!(!ct_eq(b"", b"\0"), "length differs even when padding bytes are zero");
        assert!(!ct_eq(b"a\0", b"a"));
    }
}
