use thiserror::Error;

#[derive(Debug, Error)]
pub enum UserError {
    #[error("Could not parse DN: malformed RDN '{0}' (expected key=value)")]
    InvalidDn(String),

    #[error("Attribute '{0}' not found in DN")]
    AttributeNotFound(String),
}

/// A user resolved from the mTLS client certificate subject DN.
#[derive(Debug, Clone)]
pub struct User {
    /// The configured DN attribute value (e.g. the `CN` component) used as the
    /// OIDC `sub` claim.
    pub subject: String,
    /// The raw, unmodified DN string from the proxy header.
    pub raw_dn: String,
}

/// Resolves a `User` from the value of the configured proxy header (e.g.
/// `X-Client-Cert-Subject`), which contains the client certificate's x509
/// distinguished name in RFC 4514 string form.
///
/// The parser is intentionally minimal: it splits RDNs on unescaped `,` and
/// each RDN on the first `=`. Escaped commas (`\,`) are respected. Multi-valued
/// RDNs (`+`-separated) are not specially handled and will be treated as part
/// of a single RDN's value.
pub struct UserManager {
    dn_attribute: String,
}

impl UserManager {
    pub fn new(dn_attribute: String) -> Self {
        Self { dn_attribute }
    }

    pub fn dn_attribute(&self) -> &str {
        &self.dn_attribute
    }

    pub fn resolve(&self, header_value: &str) -> Result<User, UserError> {
        let subject = extract_dn_attribute(header_value, &self.dn_attribute)?;
        Ok(User {
            subject,
            raw_dn: header_value.to_string(),
        })
    }
}

fn extract_dn_attribute(dn: &str, attribute: &str) -> Result<String, UserError> {
    let attr_upper = attribute.to_uppercase();
    for rdn in split_rdns(dn) {
        let rdn_trimmed = rdn.trim();
        let (key, value) = rdn_trimmed
            .split_once('=')
            .ok_or_else(|| UserError::InvalidDn(rdn_trimmed.to_string()))?;
        if key.trim().to_uppercase() == attr_upper {
            return Ok(value.trim().to_string());
        }
    }
    Err(UserError::AttributeNotFound(attribute.to_string()))
}

/// Split a DN into RDNs on unescaped commas. A backslash escapes the next
/// character (typically a comma), so `\,` does not start a new RDN.
fn split_rdns(dn: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let bytes = dn.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b',' {
            parts.push(&dn[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    parts.push(&dn[start..]);
    parts
}

/// Compute the effective group list for a token issued to `client_groups`
/// under the server's `default_groups`. The result is the union of the two,
/// de-duplicated, with default groups first (preserving their order) followed
/// by client-specific groups.
pub fn resolve_groups(client_groups: &[String], default_groups: &[String]) -> Vec<String> {
    let mut result: Vec<String> = default_groups.to_vec();
    for g in client_groups {
        if !result.contains(g) {
            result.push(g.clone());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cn_simple() {
        let dn = "CN=alice,OU=eng,O=acme";
        assert_eq!(extract_dn_attribute(dn, "CN").unwrap(), "alice");
    }

    #[test]
    fn test_extract_cn_case_insensitive() {
        let dn = "cn=alice,OU=eng,O=acme";
        assert_eq!(extract_dn_attribute(dn, "CN").unwrap(), "alice");
    }

    #[test]
    fn test_extract_ou() {
        let dn = "CN=alice,OU=eng,O=acme";
        assert_eq!(extract_dn_attribute(dn, "OU").unwrap(), "eng");
    }

    #[test]
    fn test_extract_o() {
        let dn = "CN=alice,OU=eng,O=acme";
        assert_eq!(extract_dn_attribute(dn, "O").unwrap(), "acme");
    }

    #[test]
    fn test_extract_missing_attribute() {
        let dn = "CN=alice,OU=eng";
        assert!(matches!(
            extract_dn_attribute(dn, "EMAIL"),
            Err(UserError::AttributeNotFound(_))
        ));
    }

    #[test]
    fn test_escaped_comma() {
        let dn = r"CN=alice\, bob,OU=eng,O=acme";
        assert_eq!(extract_dn_attribute(dn, "CN").unwrap(), r"alice\, bob");
    }

    #[test]
    fn test_malformed_rdn_returns_invalid_dn() {
        let dn = "not-a-rdn,CN=alice";
        assert!(matches!(
            extract_dn_attribute(dn, "CN"),
            // "not-a-rdn" is hit first and has no '='.
            Err(UserError::InvalidDn(_))
        ));
    }

    #[test]
    fn test_user_manager_resolve() {
        let mgr = UserManager::new("CN".to_string());
        let user = mgr.resolve("CN=alice,OU=eng,O=acme").unwrap();
        assert_eq!(user.subject, "alice");
        assert_eq!(user.raw_dn, "CN=alice,OU=eng,O=acme");
    }

    #[test]
    fn test_user_manager_missing_attr() {
        let mgr = UserManager::new("EMAIL".to_string());
        let err = mgr.resolve("CN=alice,OU=eng").unwrap_err();
        assert!(matches!(err, UserError::AttributeNotFound(_)));
    }

    #[test]
    fn test_group_resolution_default_only() {
        let default = vec!["everyone".to_string(), "authenticated".to_string()];
        let client_groups: Vec<String> = vec![];
        let result = resolve_groups(&client_groups, &default);
        assert_eq!(result, vec!["everyone", "authenticated"]);
    }

    #[test]
    fn test_group_resolution_client_only() {
        let default: Vec<String> = vec![];
        let client_groups = vec!["spa-users".to_string()];
        let result = resolve_groups(&client_groups, &default);
        assert_eq!(result, vec!["spa-users"]);
    }

    #[test]
    fn test_group_resolution_union_dedup() {
        let default = vec!["everyone".to_string(), "authenticated".to_string()];
        let client_groups = vec!["authenticated".to_string(), "spa-users".to_string()];
        let result = resolve_groups(&client_groups, &default);
        assert_eq!(result, vec!["everyone", "authenticated", "spa-users"]);
    }

    #[test]
    fn test_split_rdns_respects_escaped_comma() {
        let dn = r"a=1,b=2\,3,c=4";
        let parts = split_rdns(dn);
        assert_eq!(parts, vec!["a=1", r"b=2\,3", "c=4"]);
    }
}
