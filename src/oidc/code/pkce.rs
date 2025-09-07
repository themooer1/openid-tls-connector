use std::fmt::{Display, Formatter};

use base64::{prelude::BASE64_URL_SAFE, Engine};
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

            let should_equal_code_challenge = BASE64_URL_SAFE.encode(digest);

            code_challenge == should_equal_code_challenge
        }
    }
}