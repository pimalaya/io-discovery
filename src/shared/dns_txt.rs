//! # DNS TXT query coroutine.
//!
//! [`DiscoveryDnsTxt`] sends one DNS TXT question over TCP and parses
//! the response into TXT answer records in the order the resolver
//! delivered them (RFC 1035 imposes no priority for TXT).
//!
//! TCP framing (RFC 1035 §4.2.2: 2-byte big-endian length prefix) is
//! handled inside the coroutine, so [`WantsRead`] /
//! [`WantsWrite`] look exactly like an HTTP exchange.
//!
//! [`WantsRead`]: DiscoveryDnsTxtResult::WantsRead
//! [`WantsWrite`]: DiscoveryDnsTxtResult::WantsWrite

use core::mem;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    vec::Vec,
};

use domain::{
    new::{
        base::{
            HeaderFlags, MessageItem, QClass, QType, Question, Record,
            build::{MessageBuildError, MessageBuilder},
            name::{NameCompressor, NameParseError, RevNameBuf},
            parse::MessageParser,
            wire::{AsBytes, U16},
        },
        rdata::{RecordData, Txt},
    },
    utils::dst::UnsizedCopy,
};
use thiserror::Error;

const QUERY_BUF_SIZE: usize = 4 * 1024;

/// Errors that can occur during a single DNS TXT exchange.
#[derive(Debug, Error)]
pub enum DiscoveryDnsTxtError {
    #[error("DNS TXT domain `{1}` is not a valid name")]
    InvalidDomain(#[source] NameParseError, String),
    #[error("DNS TXT query did not fit in the {QUERY_BUF_SIZE}-byte buffer")]
    QueryTooLarge(#[source] MessageBuildError),
    #[error("DNS TXT response could not be parsed")]
    InvalidResponse(String),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryDnsTxtResult {
    /// TXT answer records in the resolver's order; empty when the
    /// response carries no TXT answers.
    Ok(Vec<Record<RevNameBuf, Box<Txt>>>),
    /// The coroutine wants more bytes from the socket.
    WantsRead,
    /// The coroutine wants the given bytes written to the socket.
    WantsWrite(Vec<u8>),
    /// The coroutine failed.
    Err(DiscoveryDnsTxtError),
}

/// Internal state of the [`DiscoveryDnsTxt`] coroutine.
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

/// I/O-free coroutine that exchanges one DNS TXT query/response pair
/// over TCP.
#[derive(Debug)]
pub struct DiscoveryDnsTxt {
    domain: String,
    state: State,
    wants_read: bool,
    wants_write: Option<Vec<u8>>,
    response: Vec<u8>,
}

impl DiscoveryDnsTxt {
    /// Returns a coroutine ready to build and emit a DNS TXT query
    /// for `domain` on the first [`resume`].
    ///
    /// [`resume`]: DiscoveryDnsTxt::resume
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
    pub fn resume(&mut self, mut arg: Option<&[u8]>) -> DiscoveryDnsTxtResult {
        loop {
            if let Some(bytes) = self.wants_write.take() {
                return DiscoveryDnsTxtResult::WantsWrite(bytes);
            }

            if mem::take(&mut self.wants_read) {
                return DiscoveryDnsTxtResult::WantsRead;
            }

            match mem::take(&mut self.state) {
                State::BuildQuery => {
                    let qname = match self.domain.parse::<RevNameBuf>() {
                        Ok(qname) => qname,
                        Err(err) => {
                            let domain = mem::take(&mut self.domain);
                            let err = DiscoveryDnsTxtError::InvalidDomain(err, domain);
                            return DiscoveryDnsTxtResult::Err(err);
                        }
                    };

                    let mut buf = vec![0u8; QUERY_BUF_SIZE];
                    let mut compressor = NameCompressor::default();
                    let mut builder = MessageBuilder::new(
                        &mut buf[2..],
                        &mut compressor,
                        U16::new(1),
                        *HeaderFlags::default().set_rd(true),
                    );

                    let q = Question {
                        qname,
                        qtype: QType::TXT,
                        qclass: QClass::IN,
                    };

                    if let Err(err) = builder.push_question(&q) {
                        let err = DiscoveryDnsTxtError::QueryTooLarge(err);
                        return DiscoveryDnsTxtResult::Err(err);
                    }

                    let msg_len = builder.finish().as_bytes().len();
                    buf[0..2].copy_from_slice(&(msg_len as u16).to_be_bytes());
                    buf.truncate(msg_len + 2);

                    self.wants_write = Some(buf);
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
                            let err = DiscoveryDnsTxtError::InvalidResponse(err.to_string());
                            return DiscoveryDnsTxtResult::Err(err);
                        }
                    };

                    let mut records: Vec<Record<RevNameBuf, Box<Txt>>> = Vec::new();

                    for item in parser {
                        let Ok(MessageItem::Answer(record)) = item else {
                            continue;
                        };

                        let RecordData::Txt(txt) = record.rdata else {
                            continue;
                        };

                        records.push(Record {
                            rname: record.rname,
                            rtype: record.rtype,
                            rclass: record.rclass,
                            ttl: record.ttl,
                            rdata: txt.unsized_copy_into(),
                        });
                    }

                    return DiscoveryDnsTxtResult::Ok(records);
                }

                State::Done => {
                    panic!("DiscoveryDnsTxt::resume called after completion")
                }
            }
        }
    }
}
