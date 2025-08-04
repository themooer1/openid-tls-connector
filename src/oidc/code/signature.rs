use std::time::Duration;

use crate::oidc::code::timestamp::TimestampError;

use super::code::AuthorizationCode;
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
        into_writer(&signed, &mut serialized);

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
