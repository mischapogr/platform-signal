//! Selected OAuth2 access-token introspection profile. Caller must first verify
//! the fixed provider transport, client authentication and successful response.
use super::{AuthenticatedIdentity, identifier};
use serde::Deserialize;
use thiserror::Error;

pub const RESPONSE_BYTES: usize = 16 * 1024;
const MAX_AUDIENCES: usize = 16;

/// Operator-selected provider identity, resource audience and finite request lease.
/// No provider groups, role names or scope strings become SIGNAL permissions.
pub struct IntrospectionProfile {
    issuer: Box<str>,
    audience: Box<str>,
    lease_seconds: u64,
}
#[derive(Debug, Error, Eq, PartialEq)]
pub enum IntrospectionError {
    #[error("invalid introspection profile")]
    Configuration,
    #[error("invalid bounded introspection response")]
    InvalidResponse,
    #[error("inactive or invalid access token")]
    Denied,
}
impl IntrospectionProfile {
    pub fn new(
        issuer: String,
        audience: String,
        lease_seconds: u64,
    ) -> Result<Self, IntrospectionError> {
        if !identifier(&issuer, 2048)
            || !identifier(&audience, 256)
            || !(1..=300).contains(&lease_seconds)
        {
            return Err(IntrospectionError::Configuration);
        }
        Ok(Self {
            issuer: issuer.into_boxed_str(),
            audience: audience.into_boxed_str(),
            lease_seconds,
        })
    }
    /// Host trust boundary: these bytes must come from the authenticated fixed
    /// backend's successful response, never a caller-supplied header/body. This
    /// parser verifies the profile; it does not prove HTTP/TLS authenticity.
    pub fn from_authenticated_response(
        &self,
        bytes: &[u8],
        now: u64,
    ) -> Result<AuthenticatedIdentity, IntrospectionError> {
        if bytes.is_empty()
            || bytes.len() > RESPONSE_BYTES
            || bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
        {
            return Err(IntrospectionError::InvalidResponse);
        }
        let response: Response =
            serde_json::from_slice(bytes).map_err(|_| IntrospectionError::InvalidResponse)?;
        if !response.active {
            return Err(IntrospectionError::Denied);
        }
        let (Some(issuer), Some(subject), Some(audience), Some(expiry), Some(token_type)) = (
            response.iss,
            response.sub,
            response.aud,
            response.exp,
            response.token_type,
        ) else {
            return Err(IntrospectionError::Denied);
        };
        if issuer != self.issuer.as_ref()
            || !identifier(&subject, 256)
            || !token_type.eq_ignore_ascii_case("Bearer")
            || expiry <= now
            || expiry > 253_402_300_799
            || response
                .nbf
                .is_some_and(|value| value > now || value >= expiry)
            || response
                .iat
                .is_some_and(|value| value > now || value >= expiry)
            || !audience.matches(&self.audience)
        {
            return Err(IntrospectionError::Denied);
        }
        let lease_end = now
            .checked_add(self.lease_seconds)
            .ok_or(IntrospectionError::Denied)?
            .min(expiry);
        AuthenticatedIdentity::from_verified_backend(issuer, subject, now, lease_end)
            .map_err(|_| IntrospectionError::Denied)
    }
}
// Recognized duplicates are rejected by Serde. Extension fields are permitted
// by RFC7662 but never retained or used to assign SIGNAL capabilities.
#[derive(Deserialize)]
struct Response {
    active: bool,
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<Audience>,
    exp: Option<u64>,
    token_type: Option<String>,
    nbf: Option<u64>,
    iat: Option<u64>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn matches(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => identifier(value, 256) && value == expected,
            Self::Many(values) => {
                !values.is_empty()
                    && values.len() <= MAX_AUDIENCES
                    && values.iter().all(|value| identifier(value, 256))
                    && values
                        .iter()
                        .enumerate()
                        .all(|(index, value)| !values[..index].contains(value))
                    && values.iter().any(|value| value == expected)
            }
        }
    }
}
#[cfg(test)]
mod tests;
