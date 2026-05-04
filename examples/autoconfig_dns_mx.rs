//! Drives the autoconfig DNS MX coroutine directly against a plain
//! `TcpStream` to a DNS resolver — no client wrapper, no
//! `pimalaya-stream`.
//!
//! ```sh
//! DOMAIN=posteo.net DNS=1.1.1.1:53 \
//!   cargo run --example autoconfig-dns-mx --features autoconfig
//! ```

use std::{
    env,
    io::{Read, Write},
    net::TcpStream,
};

use io_discovery::autoconfig::coroutines::dns_mx::{DiscoveryDnsMx, DiscoveryDnsMxResult};

fn main() {
    env_logger::init();

    let domain = env::var("DOMAIN").expect("DOMAIN env var");
    let dns = env::var("DNS").unwrap_or_else(|_| String::from("1.1.1.1:53"));

    let mut stream = TcpStream::connect(&dns).unwrap();
    let mut coroutine = DiscoveryDnsMx::new(&domain);
    let mut buf = [0u8; 4096];
    let mut arg: Option<&[u8]> = None;

    let records = loop {
        match coroutine.resume(arg.take()) {
            DiscoveryDnsMxResult::Ok(records) => break records,
            DiscoveryDnsMxResult::WantsWrite(bytes) => {
                stream.write_all(&bytes).unwrap();
            }
            DiscoveryDnsMxResult::WantsRead => {
                let n = stream.read(&mut buf).unwrap();
                arg = Some(&buf[..n]);
            }
            DiscoveryDnsMxResult::Err(err) => panic!("{err}"),
        }
    };

    for record in records {
        println!("{} {}", record.rdata.preference.get(), record.rdata.exchange);
    }
}
