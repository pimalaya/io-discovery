//! # Account configuration discovery
//!
//! This module contains the [`serde`] representation of the Mozilla
//! [Autoconfiguration].
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat

use alloc::{string::String, vec::Vec};
use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoConfig {
    pub version: String,
    pub email_provider: EmailProvider,
    #[serde(rename = "oAuth2")]
    pub oauth2: Option<OAuth2Config>,
}

impl fmt::Display for AutoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailProvider {
    pub id: String,
    #[serde(rename = "$value")]
    pub properties: Vec<EmailProviderProperty>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EmailProviderProperty {
    Domain(String),
    DisplayName(String),
    DisplayShortName(String),
    IncomingServer(Server),
    OutgoingServer(Server),
    Documentation(Documentation),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Server {
    pub r#type: ServerType,
    #[serde(rename = "$value")]
    pub properties: Vec<ServerProperty>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServerProperty {
    Hostname(String),
    Port(u16),
    SocketType(SecurityType),
    Authentication(AuthenticationType),
    OwaURL(String),
    EwsURL(String),
    UseGlobalPreferredServer(bool),
    Pop3(Pop3Config),
    Username(String),
    Password(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SecurityType {
    #[serde(rename = "plain")]
    Plain,
    #[serde(rename = "STARTTLS")]
    Starttls,
    #[serde(rename = "SSL")]
    Tls,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServerType {
    Pop3,
    Imap,
    Smtp,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AuthenticationType {
    #[serde(rename = "password-cleartext")]
    PasswordCleartext,
    #[serde(rename = "password-encrypted")]
    PasswordEncrypted,
    #[serde(rename = "NTLM")]
    Ntlm,
    #[serde(rename = "GSAPI")]
    GsApi,
    #[serde(rename = "client-IP-address")]
    ClientIPAddress,
    #[serde(rename = "TLS-client-cert")]
    TlsClientCert,
    OAuth2,
    #[serde(rename = "None")]
    None,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pop3Config {
    pub leave_messages_on_server: bool,
    pub download_on_biff: Option<bool>,
    pub days_to_leave_messages_on_server: Option<u64>,
    pub check_interval: Option<CheckInterval>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckInterval {
    pub minutes: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Documentation {
    pub url: String,
    #[serde(default, rename = "$value")]
    pub properties: Vec<DocumentationDescription>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentationDescription {
    pub lang: Option<String>,
    #[serde(rename = "$value")]
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Config {
    pub issuer: String,
    pub scope: String,
    #[serde(rename = "authURL")]
    pub auth_url: String,
    #[serde(rename = "tokenURL")]
    pub token_url: String,
}
