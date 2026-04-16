use alloc::{
    borrow::ToOwned,
    format,
    string::{FromUtf8Error, String, ToString},
};

use io_http::{rfc9110::request::HttpRequest, rfc9112::send::*};
use io_socket::io::{SocketInput, SocketOutput};
use thiserror::Error;
use url::{ParseError, Url};

/// Errors that can occur during a DNS TCP query.
#[derive(Debug, Error)]
pub enum DiscoveryIspFallbackError {
    #[error(transparent)]
    Http(#[from] Http11SendError),
    #[error("ISP fallback call returned unexpected {0} {1}")]
    Status(u16, String),
    #[error("ISP fallback call reached unexpected redirection")]
    Redirect,
    #[error("ISP fallback call returned invalid UTF-8 body")]
    Utf8Body(#[source] FromUtf8Error),
}

/// Output emitted when the coroutine terminates its progression.
pub enum DiscoveryIspFallbackResult {
    /// The coroutine has successfully decoded a DNS response.
    Ok { xml: String },
    /// A socket I/O needs to be performed to make the coroutine progress.
    Io { input: SocketInput },
    /// An error occurred during the coroutine progression.
    Err { err: DiscoveryIspFallbackError },
}

#[derive(Debug, Default)]
pub enum State {
    Send(Http11Send),
    Sending,
    Sent,
    #[default]
    Invalid,
}

pub struct DiscoveryIspFallback {
    http: Http11Send,
}

impl DiscoveryIspFallback {
    pub fn new_url(domain: impl AsRef<str>, secure: bool) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let s = if secure { "s" } else { "" };
        let url = format!("http{s}://{domain}/.well-known/autoconfig/mail/config-v1.1.xml");
        Url::parse(&url)
    }

    /// Creates a new coroutine that will query `name` for `qtype` records
    /// over TCP, using the given message `id`.
    pub fn new(url: Url) -> Self {
        let host = url.host_str().unwrap_or("127.0.0.1").to_owned();
        let req = HttpRequest::get(url).header("Host", host);
        let http = Http11Send::new(req);
        Self { http }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<SocketOutput>) -> DiscoveryIspFallbackResult {
        match self.http.resume(arg) {
            Http11SendResult::Ok { response, .. } if !response.status.is_success() => {
                let body = response.body.trim_ascii();
                let body = if body.is_empty() {
                    String::from("without body")
                } else {
                    String::from_utf8_lossy(&body).to_string()
                };

                DiscoveryIspFallbackResult::Err {
                    err: DiscoveryIspFallbackError::Status(*response.status, body),
                }
            }

            Http11SendResult::Ok { response, .. } => match String::from_utf8(response.body) {
                Ok(xml) => DiscoveryIspFallbackResult::Ok { xml },
                Err(err) => DiscoveryIspFallbackResult::Err {
                    err: DiscoveryIspFallbackError::Utf8Body(err),
                },
            },

            Http11SendResult::Io { input } => DiscoveryIspFallbackResult::Io { input },
            Http11SendResult::Err { err } => DiscoveryIspFallbackResult::Err { err: err.into() },
            Http11SendResult::Redirect { .. } => DiscoveryIspFallbackResult::Err {
                err: DiscoveryIspFallbackError::Redirect,
            },
        }
    }
}
