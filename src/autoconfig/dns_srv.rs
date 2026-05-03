//! # DNS SRV query coroutine.
//!
//! [`DiscoveryDnsSrv`] sends one DNS SRV question over TCP and parses
//! the response into [`Srv`] records sorted per RFC 2782 (ascending
//! priority, then descending weight). Records whose target is the root
//! name (RFC 2782 §3, "service not available") are dropped.
//!
//! TCP framing (RFC 1035 §4.2.2: 2-byte big-endian length prefix) is
//! handled inside the coroutine, so [`WantsRead`] /
//! [`WantsWrite`] look exactly like an HTTP exchange.
//!
//! [`WantsRead`]: DiscoveryDnsSrvResult::WantsRead
//! [`WantsWrite`]: DiscoveryDnsSrvResult::WantsWrite

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
    rdata::{RecordData, Srv},
};
use thiserror::Error;

const QUERY_BUF_SIZE: usize = 4 * 1024;

/// SRV is not exposed by `domain::new::base::QType`, so we build it
/// from its IANA-assigned code (RFC 2782).
const QTYPE_SRV: QType = QType { code: U16::new(33) };

/// Errors that can occur during a single DNS SRV exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsSrvError {
    #[error("DNS SRV qname `{1}` is not a valid name")]
    InvalidQname(#[source] NameParseError, String),
    #[error("DNS SRV query did not fit in the {QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS SRV response could not be parsed")]
    InvalidResponse(String),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryDnsSrvResult {
    /// SRV answer records sorted ascending by priority then descending
    /// by weight (RFC 2782); empty when the response carries no usable
    /// SRV answers.
    Ok(Vec<Record<RevNameBuf, Srv<NameBuf>>>),
    /// The coroutine wants more bytes from the socket.
    WantsRead,
    /// The coroutine wants the given bytes written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine failed.
    Err(DiscoveryDnsSrvError),
}

/// Internal state of the [`DiscoveryDnsSrv`] coroutine.
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

/// I/O-free coroutine that exchanges one DNS SRV query/response pair
/// over TCP.
#[derive(Debug)]
pub struct DiscoveryDnsSrv {
    qname: String,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    response: Vec<u8>,
}

impl DiscoveryDnsSrv {
    /// Returns a coroutine ready to build and emit a DNS SRV query
    /// for the fully-formed `qname` (e.g. `_imap._tcp.example.org`)
    /// on the first [`resume`].
    ///
    /// [`resume`]: DiscoveryDnsSrv::resume
    pub fn new(qname: impl ToString) -> Self {
        Self {
            qname: qname.to_string(),
            state: State::BuildQuery,
            wants_read: false,
            wants_write: None,
            response: Vec::new(),
        }
    }

    /// Advances the coroutine.
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> DiscoveryDnsSrvResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return DiscoveryDnsSrvResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return DiscoveryDnsSrvResult::WantsRead;
            }

            match mem::take(&mut self.state) {
                State::BuildQuery => {
                    let qname = match self.qname.parse::<RevNameBuf>() {
                        Ok(qname) => qname,
                        Err(err) => {
                            let raw = mem::take(&mut self.qname);
                            let err = DiscoveryDnsSrvError::InvalidQname(err, raw);
                            return DiscoveryDnsSrvResult::Err(err);
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
                        qtype: QTYPE_SRV,
                        qclass: QClass::IN,
                    };

                    if let Err(err) = builder.push_question(&q) {
                        let err = DiscoveryDnsSrvError::QueryTooLarge(err);
                        return DiscoveryDnsSrvResult::Err(err);
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
                            let err = DiscoveryDnsSrvError::InvalidResponse(err.to_string());
                            return DiscoveryDnsSrvResult::Err(err);
                        }
                    };

                    let mut records: Vec<Record<RevNameBuf, Srv<NameBuf>>> = Vec::new();

                    for item in parser {
                        let Ok(MessageItem::Answer(record)) = item else {
                            continue;
                        };

                        let RecordData::Srv(srv) = record.rdata else {
                            continue;
                        };

                        if srv.target.is_root() {
                            continue;
                        }

                        records.push(Record {
                            rname: record.rname,
                            rtype: record.rtype,
                            rclass: record.rclass,
                            ttl: record.ttl,
                            rdata: srv,
                        });
                    }

                    records.sort_by(|a, b| {
                        a.rdata
                            .priority
                            .cmp(&b.rdata.priority)
                            .then_with(|| b.rdata.weight.cmp(&a.rdata.weight))
                    });

                    return DiscoveryDnsSrvResult::Ok(records);
                }

                State::Done => {
                    panic!("DiscoveryDnsSrv::resume called after completion")
                }
            }
        }
    }
}
