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
pub enum DiscoveryIspMainError {
    #[error(transparent)]
    Http(#[from] Http11SendError),
    #[error("ISP call returned unexpected status code {0}: {1}")]
    Status(u16, String),
    #[error("ISP call reached unexpected redirection")]
    Redirect,
    #[error("ISP call returned invalid UTF-8 body: {0}")]
    Utf8Body(#[source] FromUtf8Error, String),
}

/// Output emitted when the coroutine terminates its progression.
pub enum DiscoveryIspMainResult {
    /// The coroutine has successfully decoded a DNS response.
    Ok { xml: String },

    /// A socket I/O needs to be performed to make the coroutine progress.
    Io { input: SocketInput },

    /// An error occurred during the coroutine progression.
    Err { err: DiscoveryIspMainError },
}

#[derive(Debug, Default)]
pub enum State {
    Send(Http11Send),
    Sending,
    Sent,
    #[default]
    Invalid,
}

pub struct DiscoveryIspMain {
    http: Http11Send,
}

impl DiscoveryIspMain {
    pub fn generate_url(
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
        let host = url.host_str().unwrap().to_owned();
        let req = HttpRequest::get(url).header("Host", host);
        let http = Http11Send::new(req);
        Self { http }
    }

    /// Makes the coroutine progress.
    pub fn resume(&mut self, arg: Option<SocketOutput>) -> DiscoveryIspMainResult {
        match self.http.resume(arg) {
            Http11SendResult::Ok { response, .. } => {
                let status = response.status;
                let body = String::from_utf8_lossy(&response.body).to_string();

                if !status.is_success() {
                    let err = DiscoveryIspMainError::Status(*status, body);
                    return DiscoveryIspMainResult::Err { err };
                }

                let xml = match String::from_utf8(response.body) {
                    Ok(body) => body,
                    Err(err) => {
                        let err = DiscoveryIspMainError::Utf8Body(err, body);
                        return DiscoveryIspMainResult::Err { err };
                    }
                };

                return DiscoveryIspMainResult::Ok { xml };
            }
            Http11SendResult::Io { input } => DiscoveryIspMainResult::Io { input },
            Http11SendResult::Err { err } => DiscoveryIspMainResult::Err { err: err.into() },
            Http11SendResult::Redirect { .. } => {
                let err = DiscoveryIspMainError::Redirect;
                DiscoveryIspMainResult::Err { err }
            }
        }
    }
}
