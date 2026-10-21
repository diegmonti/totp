use crate::{Error, Result};
use data_encoding::{BASE32, BASE32_NOPAD};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_RECORD_BYTES: usize = 16_384;
pub const MAX_SECRET_BYTES: usize = 1024;
fn invalid(message: &str) -> Error {
    Error::InvalidConfiguration(message.into())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}
impl std::str::FromStr for Algorithm {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SHA1" => Ok(Self::SHA1),
            "SHA256" => Ok(Self::SHA256),
            "SHA512" => Ok(Self::SHA512),
            _ => Err(invalid("supported algorithms are SHA1, SHA256, SHA512")),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialRecord {
    pub schema_version: u32,
    #[serde(rename = "type")]
    pub kind: String,
    secret: Zeroizing<String>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub t0: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}
// Deliberately no Debug implementation: the protected payload must never be formatted.
impl CredentialRecord {
    pub fn new(
        secret: &str,
        algorithm: Algorithm,
        digits: u32,
        period: u64,
        t0: u64,
        issuer: Option<String>,
        account: Option<String>,
    ) -> Result<Self> {
        let decoded = decode_secret(secret)?;
        let record = Self {
            schema_version: 1,
            kind: "totp".into(),
            secret: Zeroizing::new(BASE32_NOPAD.encode(&decoded)),
            algorithm,
            digits,
            period,
            t0,
            issuer,
            account,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 || self.kind != "totp" {
            return Err(Error::UnsupportedSchema);
        }
        if !matches!(self.digits, 6 | 8) {
            return Err(invalid("digits must be 6 or 8"));
        }
        if self.period == 0 {
            return Err(invalid("period must be greater than zero"));
        }
        if self
            .issuer
            .as_ref()
            .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
            || self
                .account
                .as_ref()
                .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
        {
            return Err(invalid(
                "metadata is too long or contains control characters",
            ));
        }
        decode_secret(&self.secret)?;
        Ok(())
    }
    pub fn decoded_secret(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_secret(&self.secret)
    }
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *bytes, self)
            .map_err(|_| invalid("record serialization failed"))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("credential record is too large"));
        }
        Ok(bytes)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("credential record is too large"));
        }
        // Inspect the version without constructing a generic JSON value containing secret copies.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Version {
            schema_version: u32,
        }
        let version: Version =
            serde_json::from_slice(bytes).map_err(|_| invalid("malformed credential record"))?;
        if version.schema_version != 1 {
            return Err(Error::UnsupportedSchema);
        }
        // A borrowed preflight rejects unknown/duplicate/missing fields before allocating a seed.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        #[allow(dead_code)]
        struct Shape<'a> {
            schema_version: u32,
            #[serde(rename = "type")]
            kind: &'a str,
            #[serde(borrow)]
            secret: &'a serde_json::value::RawValue,
            algorithm: Algorithm,
            digits: u32,
            period: u64,
            t0: u64,
            #[serde(borrow)]
            issuer: Option<&'a serde_json::value::RawValue>,
            #[serde(borrow)]
            account: Option<&'a serde_json::value::RawValue>,
        }
        let shape: Shape<'_> =
            serde_json::from_slice(bytes).map_err(|_| invalid("malformed credential record"))?;
        if shape.kind != "totp" {
            return Err(Error::UnsupportedSchema);
        }
        let record: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("malformed credential record"))?;
        record.validate()?;
        Ok(record)
    }
}
pub fn decode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES || !secret.is_ascii() {
        return Err(invalid("invalid Base32 seed"));
    }
    let normalized = Zeroizing::new(secret.to_ascii_uppercase());
    let decoded = if normalized.contains('=') {
        BASE32.decode(normalized.as_bytes())
    } else {
        BASE32_NOPAD.decode(normalized.as_bytes())
    };
    let decoded = Zeroizing::new(decoded.map_err(|_| invalid("invalid Base32 seed"))?);
    if decoded.is_empty() {
        return Err(invalid("seed is empty"));
    }
    Ok(decoded)
}
pub fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !(name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit())
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        return Err(Error::InvalidArguments(
            "identifier must match [a-z0-9][a-z0-9._-]{0,63}".into(),
        ));
    }
    Ok(())
}

pub fn parse_otpauth(input: &str) -> Result<CredentialRecord> {
    if input.len() > MAX_RECORD_BYTES {
        return Err(invalid("OTPAuth URI is too long"));
    }
    let remainder = input
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| invalid("expected otpauth://totp/ URI"))?;
    if remainder.contains('#') {
        return Err(invalid("URI fragments are unsupported"));
    }
    let (raw_label, query) = remainder
        .split_once('?')
        .ok_or_else(|| invalid("missing URI secret"))?;
    if raw_label.is_empty() || raw_label.contains('/') {
        return Err(invalid("invalid account label"));
    }
    let label = percent_decode(raw_label, false)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) if !issuer.is_empty() && !account.is_empty() => {
            (Some(issuer.to_string()), account.to_string())
        }
        Some(_) => return Err(invalid("invalid issuer or account label")),
        None => (None, label),
    };
    let mut secret = None;
    let mut issuer = None;
    let mut algorithm = Algorithm::SHA1;
    let mut digits = 6;
    let mut period = 30;
    let mut seen = std::collections::HashSet::new();
    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| invalid("malformed OTPAuth parameter"))?;
        let key = percent_decode(key, true)?;
        let value = Zeroizing::new(percent_decode(value, true)?);
        if !seen.insert(key.to_string()) {
            return Err(invalid("duplicate OTPAuth parameter"));
        }
        match key.as_str() {
            "secret" => secret = Some(value),
            "issuer" => issuer = Some(value.to_string()),
            "algorithm" => algorithm = value.parse()?,
            "digits" => digits = value.parse().map_err(|_| invalid("invalid digit count"))?,
            "period" => period = value.parse().map_err(|_| invalid("invalid period"))?,
            _ => return Err(invalid("unsupported OTPAuth parameter")),
        }
    }
    if let (Some(a), Some(b)) = (&label_issuer, &issuer) {
        if a != b {
            return Err(invalid("URI issuer does not match label issuer"));
        }
    }
    CredentialRecord::new(
        &secret.ok_or_else(|| invalid("missing URI secret"))?,
        algorithm,
        digits,
        period,
        0,
        issuer.or(label_issuer),
        Some(account),
    )
}
fn percent_decode(value: &str, plus_as_space: bool) -> Result<String> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut iter = value.bytes();
    while let Some(b) = iter.next() {
        if b == b'%' {
            let high = iter
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(|| invalid("invalid URI escaping"))?;
            let low = iter
                .next()
                .and_then(|b| (b as char).to_digit(16))
                .ok_or_else(|| invalid("invalid URI escaping"))?;
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(if plus_as_space && b == b'+' { b' ' } else { b });
        }
    }
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(value) => Ok(value),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(invalid("invalid account label encoding"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identifiers() {
        for name in ["a", "github.1_-", &"x".repeat(64)] {
            assert!(validate_identifier(name).is_ok());
        }
        for name in ["", "-x", "a/b", "é", "a b", "Github", &"x".repeat(65)] {
            assert!(validate_identifier(name).is_err());
        }
    }
    #[test]
    fn base32_validation() {
        for secret in ["", "AAAA1", "MZ", "MY=", "M Y", "💥"] {
            assert!(decode_secret(secret).is_err());
        }
        assert_eq!(&*decode_secret("my======").unwrap(), b"f");
        assert_eq!(&*decode_secret("MY").unwrap(), b"f");
    }
    #[test]
    fn record_round_trip_and_strict_schema() {
        let record = CredentialRecord::new(
            "MY",
            Algorithm::SHA512,
            8,
            60,
            12,
            Some("Issuer".into()),
            Some("Account".into()),
        )
        .unwrap();
        let bytes = record.to_bytes().unwrap();
        let parsed = CredentialRecord::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.t0, 12);
        assert_eq!(parsed.algorithm, Algorithm::SHA512);
        assert_eq!(parsed.to_bytes().unwrap(), bytes);
        let json = std::str::from_utf8(&bytes).unwrap();
        assert_eq!(
            CredentialRecord::from_bytes(
                json.replace("schemaVersion\":1", "schemaVersion\":2")
                    .as_bytes()
            )
            .err()
            .unwrap()
            .exit_code(),
            10
        );
        assert!(CredentialRecord::from_bytes(
            json.replace("\"digits\":8", "\"digits\":8,\"unknown\":true")
                .as_bytes()
        )
        .is_err());
        assert!(CredentialRecord::from_bytes(
            json.replace("\"digits\":8", "\"digits\":7").as_bytes()
        )
        .is_err());
        assert!(CredentialRecord::from_bytes(
            json.replace("\"digits\":8", "\"digits\":8,\"digits\":8")
                .as_bytes()
        )
        .is_err());
    }
    #[test]
    fn uris() {
        let record = parse_otpauth("otpauth://totp/Acme:alice%40example.com?secret=MY&issuer=Acme&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!(record.account.as_deref(), Some("alice@example.com"));
        assert_eq!(record.issuer.as_deref(), Some("Acme"));
        assert_eq!(record.algorithm, Algorithm::SHA256);
        assert_eq!(record.period, 60);
        for uri in [
            "otpauth://hotp/x?secret=MY",
            "otpauth://totp/x?secret=MY&secret=MY",
            "otpauth://totp/x?secret=MY&counter=1",
            "otpauth://totp/a:x?secret=MY&issuer=b",
            "otpauth://totp/%xx?secret=MY",
            "otpauth://totp/x?secret=MY#fragment",
            "otpauth://totp/x?secret=INVALID0",
        ] {
            assert!(parse_otpauth(uri).is_err());
        }
    }
}
