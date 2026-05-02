//! # PACC configuration document.
//!
//! `serde` representation of the JSON document defined by
//! [draft-ietf-mailmaint-pacc-02]. Field names follow the draft
//! verbatim; key casing is mixed (kebab-case `oauth-public`,
//! `content-type`; camelCase `shortName`) so each field is renamed
//! explicitly.
//!
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02

use alloc::{string::String, vec::Vec};
use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PaccConfig {
    pub protocols: Protocols,
    pub authentication: Authentication,
    pub info: Info,
}

impl fmt::Display for PaccConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Protocols {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmap: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caldav: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carddav: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webdav: Option<HttpProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imap: Option<TextProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pop3: Option<TextProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<TextProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managesieve: Option<TextProtocol>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpProtocol {
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TextProtocol {
    pub host: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Authentication {
    #[serde(rename = "oauth-public", skip_serializing_if = "Option::is_none")]
    pub oauth_public: Option<OauthPublic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OauthPublic {
    pub issuer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Info {
    pub provider: Provider,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<Help>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    #[serde(rename = "shortName", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Vec<Logo>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Logo {
    pub url: String,
    #[serde(rename = "content-type", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Help {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub developer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
}
