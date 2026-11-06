use std::{collections::HashMap, sync::Arc};

#[derive(Clone)]
pub struct Authenticator { tokens: Arc<HashMap<String, Vec<String>>> }

impl Authenticator {
    pub fn new(tokens: HashMap<String, Vec<String>>) -> Self { Self { tokens: Arc::new(tokens) } }
    pub fn acl(&self, bearer: Option<&str>) -> Option<Vec<String>> {
        let token = bearer?.strip_prefix("Bearer ")?;
        self.tokens.get(token).cloned()
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
}
