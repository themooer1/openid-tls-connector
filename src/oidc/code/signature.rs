use std::time::Duration;

use crate::oidc::code::timestamp::TimestampError;

use super::authorization_code::AuthorizationCode;
use super::timestamp::TimestampedContainer;
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use blake3::keyed_hash;
use ciborium::{de::Error as CBORError, from_reader, into_writer};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthorizationCodeVerificationError {
    #[error("authorization code timestamp was invalid")]
    InvalidTimestamp(#[from] TimestampError),

    #[error("authorization code signature was invalid")]
    InvalidSignature,

    #[error("authorization code could not be decoded from base64")]
    InvalidBase64Encoding(#[from] base64::DecodeError),

    #[error("failed to deserialize signed data container from CBOR")]
    InvalidSignedDataContainerEncoding(#[from] CBORError<std::io::Error>),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignedAuthorizationCode {
    data: Vec<u8>,
    signature: [u8; 32],
}

// Right now this is a key appropriate for BLAKE3's keyed_hash function
pub type MacKey = [u8; 32];

impl SignedAuthorizationCode {
    // Timestamps, signs and base64 encodes an AuthorizationCode for inclusion as the
    // code parameter in a URL
    pub fn sign_and_encode(authorization_code: &AuthorizationCode, hmac_key: &MacKey) -> String {
        // Timestamp the authorization code
        let timestamped = TimestampedContainer::new(authorization_code);

        // Serialize the contents of the authorization code
        let mut data = Vec::new();
        into_writer(&timestamped, &mut data).expect("failed to serialize authorization code");

        // Sign the serialized contents
        let signature: [u8; 32] = keyed_hash(hmac_key, &data).into();

        let signed = SignedAuthorizationCode { data, signature };

        // Serialize self to bytes
        let mut serialized = Vec::new();
        let _ = into_writer(&signed, &mut serialized);

        // Then b64-encode for use as code parameter in URL
        URL_SAFE.encode(serialized)
    }

    // base64 decodes self from a code parameter in a URL
    // validates signature and freshness
    pub fn decode_and_verify(
        encoded: &str,
        hmac_key: &MacKey,
        max_age: Duration,
    ) -> Result<AuthorizationCode, AuthorizationCodeVerificationError> {
        // Deserialize self from base64
        let serialized = URL_SAFE.decode(encoded)?;

        // Recover SignedAuthorizationCode from the CBOR
        let signed_code: SignedAuthorizationCode = from_reader(serialized.as_slice())?;

        // Verify signature
        let mac = keyed_hash(hmac_key, &signed_code.data);
        if mac == signed_code.signature {
            let timestamped: TimestampedContainer<AuthorizationCode> =
                from_reader(signed_code.data.as_slice())?;

            Ok(timestamped.extract(max_age)?)
        } else {
            Err(AuthorizationCodeVerificationError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::authorization_code::AuthorizationCode;
    use super::super::CodeChallengeMethod;
    use std::time::SystemTime;

    fn test_code() -> AuthorizationCode {
        AuthorizationCode {
            client_id: "test-client".to_string(),
            redirect_uri: "https://app.example/cb".to_string(),
            code_challenge: Some("challenge123".to_string()),
            code_challenge_method: CodeChallengeMethod::S256,
            timestamp: SystemTime::now(),
            subject: "test-user".to_string(),
            nonce: None,
            groups: vec!["users".to_string()],
            scope: vec!["openid".to_string()],
        }
    }

    fn test_key() -> MacKey {
        [42u8; 32]
    }

    #[test]
    fn test_sign_encode_decode_roundtrip() {
        let key = test_key();
        let code = test_code();
        let encoded = code.sign_and_encode(&key);
        let decoded = AuthorizationCode::decode_and_verify(&encoded, &key, Duration::from_secs(60))
            .expect("should decode");
        assert_eq!(decoded.client_id, "test-client");
        assert_eq!(decoded.redirect_uri, "https://app.example/cb");
        assert_eq!(decoded.subject, "test-user");
    }

    #[test]
    fn test_wrong_key_returns_invalid_signature() {
        let key = test_key();
        let wrong_key = [99u8; 32];
        let code = test_code();
        let encoded = code.sign_and_encode(&key);
        let result = AuthorizationCode::decode_and_verify(&encoded, &wrong_key, Duration::from_secs(60));
        assert!(matches!(
            result,
            Err(AuthorizationCodeVerificationError::InvalidSignature)
        ));
    }

    #[test]
    fn test_tampered_base64_returns_error() {
        let key = test_key();
        let code = test_code();
        let mut encoded = code.sign_and_encode(&key);
        // Tamper with the last character
        let last = encoded.pop().unwrap();
        encoded.push(if last == 'A' { 'B' } else { 'A' });
        let result = AuthorizationCode::decode_and_verify(&encoded, &key, Duration::from_secs(60));
        // Could be InvalidSignature or deserialization error
        assert!(result.is_err());
    }

    #[test]
    fn test_bad_base64_returns_error() {
        let key = test_key();
        let result = AuthorizationCode::decode_and_verify("not-valid-base64!!!", &key, Duration::from_secs(60));
        assert!(matches!(
            result,
            Err(AuthorizationCodeVerificationError::InvalidBase64Encoding(_))
        ));
    }

    #[test]
    fn test_expired_code_returns_not_fresh() {
        // We can't easily test expiry without manipulating time,
        // but we can use a zero-duration max_age with a tiny sleep
        let key = test_key();
        let code = test_code();
        let encoded = code.sign_and_encode(&key);
        std::thread::sleep(Duration::from_millis(10));
        let result = AuthorizationCode::decode_and_verify(&encoded, &key, Duration::ZERO);
        assert!(matches!(
            result,
            Err(AuthorizationCodeVerificationError::InvalidTimestamp(_))
        ));
    }
}
