use alloc::{
    borrow::ToOwned,
    format,
    string::{FromUtf8Error, String},
};

use io_http::{rfc9110::request::HttpRequest, rfc9112::send::*};
use io_socket::io::{SocketInput, SocketOutput};
use log::trace;
use thiserror::Error;
use url::{ParseError, Url};

use crate::autoconfig::serde::AutoConfig;

/// Errors that can occur during a DNS TCP query.
#[derive(Debug, Error)]
pub enum DiscoveryIspFallbackError {
    #[error("ISP fallback call returned unexpected {code}")]
    Status { code: u16 },
    #[error("ISP fallback call reached unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },

    #[error("ISP fallback call returned invalid UTF-8 body")]
    Utf8(#[source] FromUtf8Error),
    #[error("ISP fallback call returned invalid XML body")]
    Xml(#[source] serde_xml_rs::Error),
    #[error(transparent)]
    Http(#[from] Http11SendError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum DiscoveryIspFallbackResult {
    /// The coroutine has successfully decoded a DNS response.
    Ok { autoconfig: AutoConfig },
    /// A socket I/O needs to be performed to make the coroutine progress.
    Io { input: SocketInput },
    /// An error occurred during the coroutine progression.
    Err { err: DiscoveryIspFallbackError },
}

#[derive(Debug)]
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
                trace!("{response:?}");

                DiscoveryIspFallbackResult::Err {
                    err: DiscoveryIspFallbackError::Status {
                        code: *response.status,
                    },
                }
            }

            Http11SendResult::Ok { response, .. } => {
                trace!("{response:?}");

                let xml = match String::from_utf8(response.body) {
                    Ok(body) => body,
                    Err(err) => {
                        return DiscoveryIspFallbackResult::Err {
                            err: DiscoveryIspFallbackError::Utf8(err),
                        };
                    }
                };

                match serde_xml_rs::from_str(&xml) {
                    Ok(autoconfig) => DiscoveryIspFallbackResult::Ok { autoconfig },
                    Err(err) => DiscoveryIspFallbackResult::Err {
                        err: DiscoveryIspFallbackError::Xml(err),
                    },
                }
            }

            Http11SendResult::Io { input } => DiscoveryIspFallbackResult::Io { input },
            Http11SendResult::Err { err } => DiscoveryIspFallbackResult::Err { err: err.into() },
            Http11SendResult::Redirect { url, response, .. } => {
                trace!("{response:?}");

                DiscoveryIspFallbackResult::Err {
                    err: DiscoveryIspFallbackError::Redirect {
                        url,
                        code: *response.status,
                    },
                }
            }
        }
    }
}
