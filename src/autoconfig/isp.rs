use alloc::{
    borrow::ToOwned,
    format,
    string::{FromUtf8Error, String},
};

use io_http::{rfc9110::request::HttpRequest, rfc9112::send::*};
use log::trace;
use thiserror::Error;
use url::{ParseError, Url};

use crate::autoconfig::serde::AutoConfig;

/// Errors that can occur during a DNS TCP query.
#[derive(Debug, Error)]
pub enum DiscoveryIspError {
    #[error("ISP call returned unexpected {code}")]
    Status { code: u16 },
    #[error("ISP call reached unexpected redirection {code} to {url}")]
    Redirect { url: Url, code: u16 },

    #[error("ISP call returned invalid UTF-8 body")]
    Utf8(#[source] FromUtf8Error),
    #[error("ISP call returned invalid XML body")]
    Xml(#[source] serde_xml_rs::Error),
    #[error(transparent)]
    Http(#[from] Http11SendError),
}

/// Output emitted when the coroutine terminates its progression.
pub enum DiscoveryIspResult {
    /// The coroutine has successfully decoded a DNS response.
    Ok {
        autoconfig: AutoConfig,
    },
    /// A socket I/O needs to be performed to make the coroutine progress.
    WantsRead,
    WantsWrite(Vec<u8>),
    /// An error occurred during the coroutine progression.
    Err {
        err: DiscoveryIspError,
    },
}

#[derive(Debug)]
pub struct DiscoveryIsp {
    http: Http11Send,
}

impl DiscoveryIsp {
    pub fn new_url(
        local_part: impl AsRef<str>,
        domain: impl AsRef<str>,
        secure: bool,
    ) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let email = format!("{}@{domain}", local_part.as_ref());
        let s = if secure { "s" } else { "" };

        let path = format!("/mail/config-v1.1.xml?emailaddress={email}");
        let url = format!("http{s}://autoconfig.{domain}{path}");

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
    pub fn resume(&mut self, arg: &[u8]) -> DiscoveryIspResult {
        match self.http.resume(arg) {
            Http11SendResult::Ok { response, .. } if !response.status.is_success() => {
                trace!("{response:?}");

                DiscoveryIspResult::Err {
                    err: DiscoveryIspError::Status {
                        code: *response.status,
                    },
                }
            }

            Http11SendResult::Ok { response, .. } => {
                trace!("{response:?}");

                let xml = match String::from_utf8(response.body) {
                    Ok(body) => body,
                    Err(err) => {
                        return DiscoveryIspResult::Err {
                            err: DiscoveryIspError::Utf8(err),
                        };
                    }
                };

                match serde_xml_rs::from_str(&xml) {
                    Ok(autoconfig) => DiscoveryIspResult::Ok { autoconfig },
                    Err(err) => DiscoveryIspResult::Err {
                        err: DiscoveryIspError::Xml(err),
                    },
                }
            }

            Http11SendResult::WantsRead => DiscoveryIspResult::WantsRead,
            Http11SendResult::WantsWrite(bytes) => DiscoveryIspResult::WantsWrite(bytes),
            Http11SendResult::WantsRedirect { response, url, .. } => {
                trace!("{response:?}");

                DiscoveryIspResult::Err {
                    err: DiscoveryIspError::Redirect {
                        url,
                        code: *response.status,
                    },
                }
            }

            Http11SendResult::Err(err) => DiscoveryIspResult::Err { err: err.into() },
        }
    }
}
