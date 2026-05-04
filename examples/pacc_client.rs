//! Drives the std-blocking PACC client against a `rustls`-wrapped TCP
//! stream for the HTTPS fetch and a plain `TcpStream` for the DNS
//! digest verification — no `pimalaya-stream`.
//!
//! ```sh
//! DOMAIN=posteo.net DNS=1.1.1.1:53 \
//!   cargo run --example pacc --features pacc,client
//! ```

use std::{env, net::TcpStream, sync::Arc};

use io_discovery::pacc::{client::DiscoveryPaccClientStd, coroutine::DiscoveryPacc};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

fn main() {
    env_logger::init();

    let domain = env::var("DOMAIN").expect("DOMAIN env var");
    let dns = env::var("DNS").unwrap_or_else(|_| String::from("1.1.1.1:53"));

    let url = DiscoveryPacc::url(&domain).unwrap();
    let host = url.host_str().expect("PACC URL has a host").to_owned();
    let port = url.port_or_known_default().unwrap_or(443);

    let tcp = TcpStream::connect((host.as_str(), port)).unwrap();
    let server_name = host.try_into().unwrap();
    let config = ClientConfig::with_platform_verifier().unwrap();
    let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let https = StreamOwned::new(conn, tcp);

    let dns = TcpStream::connect(&dns).unwrap();

    let config = DiscoveryPaccClientStd::new(https, dns)
        .discover(&domain)
        .unwrap();

    println!("{config:#?}");
}
