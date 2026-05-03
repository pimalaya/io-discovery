//! # Mozilla autoconfig "mailconf" TXT discovery coroutine.
//!
//! [`DiscoveryMailconf`] wraps the shared [`DiscoveryDnsTxt`]
//! coroutine to query TXT records for a domain and locate one
//! prefixed with `mailconf=`. Per the Mozilla
//! [Autoconfiguration] convention, that prefix introduces a URL
//! pointing at an autoconfig XML document.
//!
//! Per RFC 1035 §3.3.14 a TXT record is a sequence of length-prefixed
//! character-strings. Long values may be split across multiple
//! character-strings; the coroutine concatenates them (no separator,
//! per RFC 6376 §3.6.2.2 / RFC 7208 §3.3) before checking the prefix.
//!
//! Per-record failures (missing `mailconf=` prefix, non-UTF-8 value,
//! malformed URL) are skipped silently — the coroutine only fails if
//! no record at the queried name yields a valid URL.
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration

use core::str::from_utf8;

use alloc::{string::ToString, vec::Vec};

use log::trace;
use thiserror::Error;
use url::Url;

use crate::dns_txt::{DiscoveryDnsTxt, DiscoveryDnsTxtError, DiscoveryDnsTxtResult};

const MAILCONF_PREFIX: &[u8] = b"mailconf=";

/// Errors that can occur during a single mailconf discovery.
#[derive(Debug, Error)]
pub enum DiscoveryMailconfError {
    #[error(transparent)]
    Dns(#[from] DiscoveryDnsTxtError),
    #[error("no `mailconf=` TXT record found for the queried domain")]
    NoMailconfRecord,
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryMailconfResult {
    /// Discovery succeeded: a TXT record carried a valid `mailconf=`
    /// URL.
    Ok(Url),
    /// The coroutine wants more bytes from the active stream.
    WantsRead,
    /// The coroutine wants the given bytes written to the active stream.
    WantsWrite(Vec<u8>),
    /// Discovery failed.
    Err(DiscoveryMailconfError),
}

/// I/O-free coroutine that performs a TXT lookup and extracts the
/// first valid `mailconf=<URL>` value.
pub struct DiscoveryMailconf {
    txt: DiscoveryDnsTxt,
}

impl DiscoveryMailconf {
    /// Returns a coroutine ready to query `domain` for TXT records on
    /// the first [`resume`].
    ///
    /// [`resume`]: DiscoveryMailconf::resume
    pub fn new(domain: impl ToString) -> Self {
        Self {
            txt: DiscoveryDnsTxt::new(domain),
        }
    }

    /// Drives the discovery coroutine for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryMailconfResult {
        match self.txt.resume(arg) {
            DiscoveryDnsTxtResult::WantsRead => DiscoveryMailconfResult::WantsRead,
            DiscoveryDnsTxtResult::WantsWrite(bytes) => DiscoveryMailconfResult::WantsWrite(bytes),
            DiscoveryDnsTxtResult::Err(err) => DiscoveryMailconfResult::Err(err.into()),
            DiscoveryDnsTxtResult::Ok(records) => {
                for record in records {
                    let mut joined = Vec::new();

                    for cs in record.rdata.iter() {
                        joined.extend_from_slice(&cs.octets);
                    }

                    let Some(value) = joined.strip_prefix(MAILCONF_PREFIX) else {
                        trace!("no `mailconf=` prefix in TXT record, skip");
                        continue;
                    };

                    let Ok(url_str) = from_utf8(value) else {
                        trace!("`mailconf=` TXT value is not valid UTF-8, skip");
                        continue;
                    };

                    let Ok(url) = Url::parse(url_str.trim()) else {
                        trace!("`mailconf=` TXT value `{url_str}` is not a valid URL, skip");
                        continue;
                    };

                    return DiscoveryMailconfResult::Ok(url);
                }

                DiscoveryMailconfResult::Err(DiscoveryMailconfError::NoMailconfRecord)
            }
        }
    }
}
