//! DNS A/AAAA lookup over UDP using the synchronous `std` runtime.
//!
//! # Usage
//!
//! ```sh
//! DOMAIN=pimalaya.org cargo run --example std_udp_query
//! ```

use std::{env, net::UdpSocket};

use io_discovery::rfc1035::{
    query_udp::{DnsUdpQuery, DnsUdpQueryResult},
    types::{
        record_data::DnsRecordData,
        r#type::{A, MX},
    },
};
use io_discovery::rfc3596::aaaa::{AAAA, DnsAaaaData};
use io_socket::runtimes::std_udp_socket::handle;

/// Google's public DNS resolver.
const DNS_SERVER: &str = "8.8.8.8:53";

fn main() {
    env_logger::init();

    let domain = env::var("DOMAIN").unwrap_or_else(|_| "pimalaya.org".to_owned());

    println!("Querying A records for {domain:?} via {DNS_SERVER} …");
    query_and_print(&domain, A);

    println!();
    println!("Querying AAAA records for {domain:?} via {DNS_SERVER} …");
    query_and_print(&domain, AAAA);

    println!();
    println!("Querying MX records for {domain:?} via {DNS_SERVER} …");
    query_and_print(&domain, MX);
}

fn query_and_print(domain: &str, qtype: impl Into<u16>) {
    let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(DNS_SERVER).unwrap();

    let mut query = DnsUdpQuery::new(0x1337, domain, qtype);
    let mut arg = None;

    let message = loop {
        match query.resume(arg.take()) {
            DnsUdpQueryResult::Ok { message } => break message,
            DnsUdpQueryResult::Io { input } => arg = Some(handle(&mut socket, input).unwrap()),
            DnsUdpQueryResult::Err { err } => panic!("query error: {err}"),
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
                    println!("  AAAA  {}", aaaa.addr);
                    continue;
                }
            }
        }

        match &rr.data {
            DnsRecordData::A(addr) => println!("  A     {addr}"),
            DnsRecordData::Mx {
                preference,
                exchange,
            } => {
                println!("  MX    {preference} {exchange}");
            }
            DnsRecordData::Ns(ns) => println!("  NS    {ns}"),
            DnsRecordData::Cname(target) => println!("  CNAME {target}"),
            DnsRecordData::Txt(strings) => {
                for s in strings {
                    println!("  TXT   {s:?}");
                }
            }
            other => println!("  {:?}", other),
        }
    }
}
