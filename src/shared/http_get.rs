//! # Shared HTTP GET coroutine
//!
//! [`HttpGet`] sends one HTTP/1.1 GET on a fully-qualified [`Url`]
//! and returns the raw response body bytes. It rejects redirects and
//! non-success status codes — both autoconfig and PACC need the
//! response that came from the original origin.
//!
//! Body deserialization is the caller's responsibility: autoconfig
//! parses the bytes as XML, PACC parses them as JSON and also keeps
//! the raw bytes for digest verification.

use alloc::{borrow::ToOwned, vec::Vec};

use io_http::{
    rfc9110::request::HttpRequest,
    rfc9112::send::{Http11Send, Http11SendError, Http11SendResult},
};
use log::trace;
use thiserror::Error;
use url::Url;

/// Errors that can occur during a single HTTP GET exchange.
#[derive(Debug, Error)]
pub enum HttpGetError {
    #[error("HTTP GET returned unexpected status {0}")]
    Status(u16),
    #[error("HTTP GET reached unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },
    #[error(transparent)]
    Http(#[from] Http11SendError),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum HttpGetResult {
    /// The GET completed with a successful response; the raw body
    /// bytes are returned for the caller to decode.
    Ok(Vec<u8>),
    /// The GET wants more bytes to be read from the socket.
    WantsRead,
    /// The GET wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The GET failed; the runtime should treat this URL as
    /// unreachable.
    Err(HttpGetError),
}

/// I/O-free coroutine that performs one HTTP GET and yields the
/// response body as raw bytes.
pub struct HttpGet {
    send: Http11Send,
}

impl HttpGet {
    /// Builds a GET for `url`. Pair with an HTTP session opened on
    /// the same URL.
    pub fn new(url: Url) -> Self {
        let host = url.host_str().unwrap_or("127.0.0.1").to_owned();
        let req = HttpRequest::get(url).header("Host", host);

        Self {
            send: Http11Send::new(req),
        }
    }

    /// Drives the GET coroutine for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> HttpGetResult {
        match self.send.resume(arg) {
            Http11SendResult::Ok { response, .. } if !response.status.is_success() => {
                trace!("{response:?}");
                HttpGetResult::Err(HttpGetError::Status(*response.status))
            }
            Http11SendResult::Ok { response, .. } => {
                trace!("{response:?}");
                HttpGetResult::Ok(response.body)
            }
            Http11SendResult::WantsRead => HttpGetResult::WantsRead,
            Http11SendResult::WantsWrite(bytes) => HttpGetResult::WantsWrite(bytes),
            Http11SendResult::WantsRedirect { response, url, .. } => {
                trace!("{response:?}");
                HttpGetResult::Err(HttpGetError::Redirect {
                    url,
                    code: *response.status,
                })
            }
            Http11SendResult::Err(err) => HttpGetResult::Err(err.into()),
        }
    }
}
