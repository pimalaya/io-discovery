//! # Autoconfig discovery types
//!
//! `serde` representation of the Mozilla [Autoconfiguration] XML
//! configuration document. Containers default to camelCase via
//! `#[serde(rename_all = "camelCase")]`; spec-flavoured names that
//! diverge from camelCase (`oAuth2`, `STARTTLS`, `SSL`,
//! `password-cleartext`, `authURL`, `descr`, …) are accepted on
//! deserialize via `#[serde(alias = "...")]` so XML parsing matches
//! the spec while JSON serialization stays clean camelCase and
//! round-trips JSON cleanly.
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat

use core::fmt;

use alloc::{string::String, vec::Vec};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Autoconfig {
    pub version: String,
    pub email_provider: EmailProvider,
    #[serde(alias = "oAuth2")]
    pub oauth2: Option<OAuth2Config>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailProvider {
    pub id: String,
    #[serde(default)]
    pub domain: Vec<String>,
    pub display_name: Option<String>,
    pub display_short_name: Option<String>,
    #[serde(default)]
    pub incoming_server: Vec<Server>,
    #[serde(default)]
    pub outgoing_server: Vec<Server>,
    #[serde(default)]
    pub documentation: Vec<Documentation>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Server {
    pub r#type: ServerType,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub socket_type: Option<SecurityType>,
    pub username: Option<String>,
    #[serde(default)]
    pub authentication: Vec<AuthenticationType>,
    pub pop3: Option<Pop3Config>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ServerType {
    Pop3,
    Imap,
    Smtp,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityType {
    Plain,
    #[serde(alias = "STARTTLS")]
    Starttls,
    #[serde(alias = "SSL")]
    Tls,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationType {
    #[serde(alias = "password-cleartext")]
    PasswordCleartext,
    #[serde(alias = "password-encrypted")]
    PasswordEncrypted,
    #[serde(alias = "NTLM")]
    Ntlm,
    #[serde(alias = "GSAPI")]
    GsApi,
    #[serde(alias = "client-IP-address")]
    ClientIPAddress,
    #[serde(alias = "TLS-client-cert")]
    TlsClientCert,
    #[serde(alias = "OAuth2")]
    OAuth2,
    None,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pop3Config {
    pub leave_messages_on_server: Option<bool>,
    pub download_on_biff: Option<bool>,
    pub days_to_leave_messages_on_server: Option<u64>,
    pub check_interval: Option<CheckInterval>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckInterval {
    pub minutes: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Documentation {
    pub url: String,
    #[serde(default, alias = "descr")]
    pub descriptions: Vec<Description>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    pub lang: Option<String>,
    #[serde(alias = "$value")]
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Config {
    pub issuer: String,
    pub scope: String,
    #[serde(alias = "authURL")]
    pub auth_url: String,
    #[serde(alias = "tokenURL")]
    pub token_url: String,
}

impl fmt::Display for Autoconfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = &self.email_provider;

        match (&p.display_name, &p.display_short_name) {
            (Some(n), Some(s)) => writeln!(f, "{n} ({s})")?,
            (Some(n), None) | (None, Some(n)) => writeln!(f, "{n}")?,
            (None, None) => writeln!(f, "{}", p.id)?,
        }

        if !p.domain.is_empty() {
            writeln!(f, "{}", p.domain.join(", "))?;
        }

        if !p.incoming_server.is_empty() {
            writeln!(f, "\nIncoming")?;
            for s in &p.incoming_server {
                writeln!(f, "  {s}")?;
            }
        }

        if !p.outgoing_server.is_empty() {
            writeln!(f, "\nOutgoing")?;
            for s in &p.outgoing_server {
                writeln!(f, "  {s}")?;
            }
        }

        if let Some(o) = &self.oauth2 {
            writeln!(f, "\nOAuth2")?;
            writeln!(f, "{o}")?;
        }

        if !p.documentation.is_empty() {
            writeln!(f, "\nDocumentation")?;
            for d in &p.documentation {
                writeln!(f, "  {d}")?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_label = match self.r#type {
            ServerType::Imap => "imap",
            ServerType::Pop3 => "pop3",
            ServerType::Smtp => "smtp",
        };
        write!(
            f,
            "{type_label:6}{}",
            self.hostname.as_deref().unwrap_or("?")
        )?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(sec) = &self.socket_type {
            let label = match sec {
                SecurityType::Plain => "Plain",
                SecurityType::Starttls => "STARTTLS",
                SecurityType::Tls => "SSL",
            };
            write!(f, " ({label})")?;
        }

        let mut first = true;
        for auth in &self.authentication {
            f.write_str(if first { " " } else { ", " })?;
            first = false;
            f.write_str(match auth {
                AuthenticationType::PasswordCleartext => "password-cleartext",
                AuthenticationType::PasswordEncrypted => "password-encrypted",
                AuthenticationType::Ntlm => "NTLM",
                AuthenticationType::GsApi => "GSAPI",
                AuthenticationType::ClientIPAddress => "client-IP-address",
                AuthenticationType::TlsClientCert => "TLS-client-cert",
                AuthenticationType::OAuth2 => "OAuth2",
                AuthenticationType::None => "none",
            })?;
        }

        Ok(())
    }
}

impl fmt::Display for Documentation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.descriptions.first() {
            Some(Description {
                lang: Some(lang),
                text,
            }) => write!(f, "{} ({lang}: {text})", self.url),
            Some(Description { lang: None, text }) => write!(f, "{} {text}", self.url),
            None => write!(f, "{}", self.url),
        }
    }
}

impl fmt::Display for OAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  {:11}{}", "Issuer", self.issuer)?;
        writeln!(f, "  {:11}{}", "Scope", self.scope)?;
        writeln!(f, "  {:11}{}", "Auth URL", self.auth_url)?;
        write!(f, "  {:11}{}", "Token URL", self.token_url)
    }
}
