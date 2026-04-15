//! DNS A record lookup over TCP using the synchronous `std` runtime.
//!
//! DNS over TCP (RFC 1035 §4.2.2) is used when the UDP response is truncated
//! or when the client prefers a reliable transport. The message is prefixed
//! with a 2-byte big-endian length field.
//!
//! # Usage
//!
//! ```sh
//! DOMAIN=pimalaya.org cargo run --example std_tcp_query
//! ```

use std::{env, net::TcpStream};

use io_discovery::rfc1035::{
    query_tcp::{DnsTcpQuery, DnsTcpQueryResult},
    types::{record_data::DnsRecordData, r#type::A},
};
use io_discovery::rfc3596::aaaa::{AAAA, DnsAaaaData};
use io_socket::runtimes::std_stream::handle;

/// Google's public DNS resolver.
const DNS_SERVER: &str = "8.8.8.8:53";

fn main() {
    env_logger::init();

    let domain = env::var("DOMAIN").unwrap_or_else(|_| "pimalaya.org".to_owned());

    println!("Querying A records for {domain:?} via {DNS_SERVER} (TCP) …");

    let mut stream = TcpStream::connect(DNS_SERVER).unwrap();

    let mut query = DnsTcpQuery::new(0x1337, &domain, A);
    let mut arg = None;

    let message = loop {
        match query.resume(arg.take()) {
            DnsTcpQueryResult::Ok { message } => break message,
            DnsTcpQueryResult::Io { input } => arg = Some(handle(&mut stream, input).unwrap()),
            DnsTcpQueryResult::Err { err } => panic!("query error: {err}"),
        }
    };

    if message.answers.is_empty() {
        println!("  (no records)");
        return;
    }

    for rr in &message.answers {
        if rr.r#type == AAAA {
            if let DnsRecordData::Other(data) = &rr.data {
                if let Ok(aaaa) = DnsAaaaData::decode(data) {
                    println!("  AAAA {}", aaaa.addr);
                    continue;
                }
            }
        }
        match &rr.data {
            DnsRecordData::A(addr) => println!("  A    {addr}"),
            other => println!("  {:?}", other),
        }
    }
}
