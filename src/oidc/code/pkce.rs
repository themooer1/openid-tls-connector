use std::fmt::{Display, Formatter};

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}

impl Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeChallengeMethod::Plain => f.write_str("plain"),
            CodeChallengeMethod::S256 => f.write_str("S256"),
        }
    }
}

pub fn verify_pkce(method: CodeChallengeMethod, code_challenge: &str, code_verifier: &str) -> bool
{
    match method {
        CodeChallengeMethod::Plain => {
            code_challenge == code_verifier
        },
        CodeChallengeMethod::S256 => {
            let digest = Sha256::digest(code_verifier);

            let should_equal_code_challenge = BASE64_URL_SAFE_NO_PAD.encode(digest);

            code_challenge == should_equal_code_challenge
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plain_pkce_match() {
        let verifier = "some-random-verifier";
        assert!(verify_pkce(CodeChallengeMethod::Plain, verifier, verifier));
    }

    #[test]
    fn test_plain_pkce_mismatch() {
        assert!(!verify_pkce(CodeChallengeMethod::Plain, "challenge", "verifier"));
    }

    #[test]
    fn test_s256_pkce_match() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let digest = Sha256::digest(verifier);
        let challenge = BASE64_URL_SAFE_NO_PAD.encode(digest);
        assert!(verify_pkce(CodeChallengeMethod::S256, &challenge, verifier));
    }

    #[test]
    fn test_s256_pkce_mismatch() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(!verify_pkce(CodeChallengeMethod::S256, challenge, "wrong-verifier"));
    }

    #[test]
    fn test_s256_known_vector() {
        // RFC 7636 Appendix B example
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let digest = Sha256::digest(verifier);
        let challenge = BASE64_URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(challenge, expected_challenge);
        assert!(verify_pkce(CodeChallengeMethod::S256, expected_challenge, verifier));
    }
}