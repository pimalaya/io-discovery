//! # PACC integrity verification.
//!
//! [`DiscoveryPaccVerify`] queries the `_ua-auto-config.<domain>` TXT
//! record, parses its `v=UAAC1; a=sha256; d=<base64>` content, and
//! compares the embedded digest to a SHA-256 of the supplied
//! configuration body bytes.
//!
//! The TXT exchange is delegated to [`DiscoveryDnsTxt`], so this
//! coroutine produces the same `WantsRead`/`WantsWrite` shape as any
//! other DNS-driven discovery step.
//!
//! Per [draft-ietf-mailmaint-pacc-02], `sha256` is currently the only
//! supported digest algorithm.
//!
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use domain::new::{
    base::{Record, name::RevNameBuf},
    rdata::Txt,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::dns_txt::{DiscoveryDnsTxt, DiscoveryDnsTxtError, DiscoveryDnsTxtResult};

const VERSION_TAG: &str = "UAAC1";
const ALG_SHA256: &str = "sha256";

/// Errors that can occur during a PACC integrity verification.
#[derive(Debug, Error)]
pub enum DiscoveryPaccVerifyError {
    #[error("no `_ua-auto-config` TXT record found")]
    MissingTxt,
    #[error("PACC TXT record is missing the `{0}` tag")]
    MissingTag(&'static str),
    #[error("PACC TXT record has unsupported version `{0}`, expected `UAAC1`")]
    UnsupportedVersion(String),
    #[error("PACC TXT record has unsupported digest algorithm `{0}`, expected `sha256`")]
    UnsupportedAlgorithm(String),
    #[error("PACC TXT record digest is not valid base64: {0}")]
    InvalidDigest(base64::DecodeError),
    #[error("PACC TXT record digest does not match the configuration body")]
    DigestMismatch,
    #[error(transparent)]
    Dns(#[from] DiscoveryDnsTxtError),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryPaccVerifyResult {
    /// The configuration body matches the published digest.
    Ok,
    /// The coroutine wants more bytes from the socket.
    WantsRead,
    /// The coroutine wants the given bytes written to the socket.
    WantsWrite(Vec<u8>),
    /// The verification failed.
    Err(DiscoveryPaccVerifyError),
}

/// Verifies that a PACC configuration body matches the `sha256`
/// digest published in the `_ua-auto-config.<domain>` TXT record.
pub struct DiscoveryPaccVerify {
    txt: DiscoveryDnsTxt,
    body: Vec<u8>,
}

impl DiscoveryPaccVerify {
    /// Builds a verifier that will check `body` against the digest
    /// published under `domain`.
    pub fn new(domain: impl AsRef<str>, body: Vec<u8>) -> Self {
        let domain = domain.as_ref().trim_matches('.');
        let qname = format!("_ua-auto-config.{domain}");

        Self {
            txt: DiscoveryDnsTxt::new(qname),
            body,
        }
    }

    /// Drives the verifier for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryPaccVerifyResult {
        match self.txt.resume(arg) {
            DiscoveryDnsTxtResult::Ok(records) => {
                let Some(raw) = collect_uaac1_record(records) else {
                    let err = DiscoveryPaccVerifyError::MissingTxt;
                    return DiscoveryPaccVerifyResult::Err(err);
                };

                match verify_against(&raw, &self.body) {
                    Ok(()) => DiscoveryPaccVerifyResult::Ok,
                    Err(err) => DiscoveryPaccVerifyResult::Err(err),
                }
            }
            DiscoveryDnsTxtResult::WantsRead => DiscoveryPaccVerifyResult::WantsRead,
            DiscoveryDnsTxtResult::WantsWrite(bytes) => {
                DiscoveryPaccVerifyResult::WantsWrite(bytes)
            }
            DiscoveryDnsTxtResult::Err(err) => DiscoveryPaccVerifyResult::Err(err.into()),
        }
    }
}

/// Joins the TXT character-strings of the first record whose first
/// string carries a `v=UAAC1` tag, then returns it as UTF-8.
fn collect_uaac1_record(records: Vec<Record<RevNameBuf, Box<Txt>>>) -> Option<String> {
    for record in records {
        let mut joined = Vec::new();
        for cs in record.rdata.iter() {
            joined.extend_from_slice(&cs.octets);
        }
        let s = match core::str::from_utf8(&joined) {
            Ok(s) => s.trim(),
            Err(_) => continue,
        };
        if has_uaac1_version(s) {
            return Some(s.to_string());
        }
    }
    None
}

fn has_uaac1_version(s: &str) -> bool {
    parse_tag(s, "v")
        .map(|v| v.eq_ignore_ascii_case(VERSION_TAG))
        .unwrap_or(false)
}

/// Parses one tag value out of a `v=…; a=…; d=…` record. Whitespace
/// around the `=` and `;` separators is tolerated per the draft's ABNF.
fn parse_tag<'a>(record: &'a str, tag: &str) -> Option<&'a str> {
    for part in record.split(';') {
        let part = part.trim();
        let (k, v) = part.split_once('=')?;
        if k.trim().eq_ignore_ascii_case(tag) {
            return Some(v.trim());
        }
    }
    None
}

fn verify_against(record: &str, body: &[u8]) -> Result<(), DiscoveryPaccVerifyError> {
    let version = parse_tag(record, "v").ok_or(DiscoveryPaccVerifyError::MissingTag("v"))?;
    if !version.eq_ignore_ascii_case(VERSION_TAG) {
        return Err(DiscoveryPaccVerifyError::UnsupportedVersion(
            version.to_string(),
        ));
    }

    let alg = parse_tag(record, "a").ok_or(DiscoveryPaccVerifyError::MissingTag("a"))?;
    if !alg.eq_ignore_ascii_case(ALG_SHA256) {
        return Err(DiscoveryPaccVerifyError::UnsupportedAlgorithm(
            alg.to_string(),
        ));
    }

    let digest_b64 = parse_tag(record, "d").ok_or(DiscoveryPaccVerifyError::MissingTag("d"))?;
    let expected = BASE64
        .decode(digest_b64)
        .map_err(DiscoveryPaccVerifyError::InvalidDigest)?;

    let actual = Sha256::digest(body);

    if expected.ct_eq(actual.as_slice()).into() {
        Ok(())
    } else {
        Err(DiscoveryPaccVerifyError::DigestMismatch)
    }
}
