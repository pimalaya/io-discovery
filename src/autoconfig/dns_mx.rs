//! # DNS MX query coroutine.
//!
//! [`DiscoveryDnsMx`] sends one DNS MX question over TCP and parses
//! the response into MX answer records sorted by ascending preference
//! (best first, per RFC 5321 §5.1).
//!
//! TCP framing (RFC 1035 §4.2.2: 2-byte big-endian length prefix) is
//! handled inside the coroutine, so [`WantsRead`] /
//! [`WantsWrite`] look exactly like an HTTP exchange — callers do
//! `stream.write(bytes)` / `stream.read(&mut buf)` and feed bytes
//! back as `arg`.
//!
//! Typical driver shape:
//!
//! ```ignore
//! let mut dns = DiscoveryDnsMx::new(domain);
//! let mut arg = None;
//! let mut buf = [0u8; 4096];
//! let records = loop {
//!     match dns.resume(arg) {
//!         DiscoveryDnsMxResult::Ok(records)     => break records,
//!         DiscoveryDnsMxResult::WantsWrite(ref bytes) => {
//!             stream.write_all(bytes)?;
//!             arg = None;
//!         }
//!         DiscoveryDnsMxResult::WantsRead       => {
//!             let n = stream.read(&mut buf)?;
//!             arg = Some(&buf[..n]);
//!         }
//!         DiscoveryDnsMxResult::Err(err)        => bail!(err),
//!     }
//! };
//! ```
//!
//! [`WantsRead`]: DiscoveryDnsMxResult::WantsRead
//! [`WantsWrite`]: DiscoveryDnsMxResult::WantsWrite

use core::mem;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use domain::new::{
    base::{
        HeaderFlags, MessageItem, QClass, QType, Question, Record,
        build::{MessageBuildError, MessageBuilder},
        name::{NameBuf, NameCompressor, NameParseError, RevNameBuf},
        parse::MessageParser,
        wire::{AsBytes, U16},
    },
    rdata::{Mx, RecordData},
};
use thiserror::Error;

const QUERY_BUF_SIZE: usize = 4 * 1024;

/// Errors that can occur during a single DNS MX exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsMxError {
    #[error("DNS MX domain `{1}` is not a valid name")]
    InvalidDomain(#[source] NameParseError, String),
    #[error("DNS MX query did not fit in the {QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS MX response could not be parsed")]
    InvalidResponse(String),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryDnsMxResult {
    /// MX answer records sorted by ascending preference (best first);
    /// empty when the response carries no MX answers.
    Ok(Vec<Record<RevNameBuf, Mx<NameBuf>>>),
    /// The coroutine wants more bytes from the socket.
    WantsRead,
    /// The coroutine wants the given bytes written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine failed.
    Err(DiscoveryDnsMxError),
}

/// Internal state of the [`DiscoveryDnsMx`] coroutine.
#[derive(Debug, Default)]
enum State {
    /// First step: the coroutine still has to build the query message.
    BuildQuery,
    /// The query has been emitted; the coroutine is buffering response
    /// bytes until the 2-byte length prefix and full body are present.
    ParseResponse,
    /// `Ok` or `Err` has already been returned.
    #[default]
    Done,
}

/// I/O-free coroutine that exchanges one DNS MX query/response pair
/// over TCP.
#[derive(Debug)]
pub struct DiscoveryDnsMx {
    domain: String,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    response: Vec<u8>,
}

impl DiscoveryDnsMx {
    /// Returns a coroutine ready to build and emit a DNS MX query for
    /// `domain` on the first [`resume`].
    ///
    /// [`resume`]: DiscoveryDnsMx::resume
    pub fn new(domain: impl ToString) -> Self {
        Self {
            domain: domain.to_string(),
            state: State::BuildQuery,
            wants_read: false,
            wants_write: None,
            response: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> DiscoveryDnsMxResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return DiscoveryDnsMxResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return DiscoveryDnsMxResult::WantsRead;
            }

            match mem::take(&mut self.state) {
                State::BuildQuery => {
                    let qname = match self.domain.parse::<RevNameBuf>() {
                        Ok(qname) => qname,
                        Err(err) => {
                            let domain = mem::take(&mut self.domain);
                            let err = DiscoveryDnsMxError::InvalidDomain(err, domain);
                            return DiscoveryDnsMxResult::Err(err);
                        }
                    };

                    let mut buf = [0u8; QUERY_BUF_SIZE];
                    let mut compressor = NameCompressor::default();
                    let mut builder = MessageBuilder::new(
                        &mut buf[2..],
                        &mut compressor,
                        U16::new(1),
                        *HeaderFlags::default().set_rd(true),
                    );

                    let q = Question {
                        qname,
                        qtype: QType::MX,
                        qclass: QClass::IN,
                    };

                    if let Err(err) = builder.push_question(&q) {
                        let err = DiscoveryDnsMxError::QueryTooLarge(err);
                        return DiscoveryDnsMxResult::Err(err);
                    }

                    let msg_len = builder.finish().as_bytes().len();
                    buf[0..2].copy_from_slice(&(msg_len as u16).to_be_bytes());

                    self.wants_write = Some(buf[..2 + msg_len].to_vec());
                    self.wants_read = true;
                    self.state = State::ParseResponse;
                }

                State::ParseResponse => {
                    if let Some(bytes) = arg.take() {
                        self.response.extend_from_slice(bytes);
                    }

                    if self.response.len() < 2 {
                        self.wants_read = true;
                        self.state = State::ParseResponse;
                        continue;
                    }

                    let body_len =
                        u16::from_be_bytes([self.response[0], self.response[1]]) as usize;

                    if self.response.len() < 2 + body_len {
                        self.wants_read = true;
                        self.state = State::ParseResponse;
                        continue;
                    }

                    let parser = match MessageParser::new(&self.response[2..2 + body_len]) {
                        Ok(parser) => parser,
                        Err(err) => {
                            let err = DiscoveryDnsMxError::InvalidResponse(err.to_string());
                            return DiscoveryDnsMxResult::Err(err);
                        }
                    };

                    let mut records: Vec<Record<RevNameBuf, Mx<NameBuf>>> = Vec::new();

                    for item in parser {
                        let Ok(MessageItem::Answer(record)) = item else {
                            continue;
                        };

                        let RecordData::Mx(mx) = record.rdata else {
                            continue;
                        };

                        records.push(Record {
                            rname: record.rname,
                            rtype: record.rtype,
                            rclass: record.rclass,
                            ttl: record.ttl,
                            rdata: mx,
                        });
                    }

                    records.sort_by(|a, b| a.rdata.cmp(&b.rdata));

                    return DiscoveryDnsMxResult::Ok(records);
                }

                State::Done => {
                    panic!("DiscoveryDnsMx::resume called after completion")
                }
            }
        }
    }
}

/// Strips the leftmost label of an MX target so that ISP autoconfig
/// URLs can be retried against the registrable parent
/// (`mx.example.com` → `example.com`). Returns `None` for inputs with
/// fewer than two dots after trailing-dot trimming.
pub fn mx_parent_domain(target: &str) -> Option<String> {
    let target = target.trim_end_matches('.');

    let mut first_dot = None;

    for (i, b) in target.bytes().enumerate() {
        if b != b'.' {
            continue;
        }

        if let Some(start) = first_dot {
            return Some(target[start + 1..].to_string());
        }

        first_dot = Some(i);
    }

    None
}
