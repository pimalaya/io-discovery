//! Shared helpers for integration tests.

#![allow(dead_code)]

use std::{
    net::UdpSocket,
    sync::atomic::{AtomicU16, Ordering},
};

use io_discovery::rfc1035::{
    query_udp::{DnsUdpQuery, DnsUdpQueryResult},
    types::message::DnsMessage,
};
use io_socket::runtimes::std_udp_socket::handle;

/// Google Public DNS, used as the resolver for all integration tests.
pub const DNS_SERVER: &str = "8.8.8.8:53";

static NEXT_ID: AtomicU16 = AtomicU16::new(1);

/// Sends a single DNS query over UDP to [`DNS_SERVER`] and returns the
/// decoded response.
pub fn udp_query(name: &str, qtype: impl Into<u16>) -> DnsMessage {
    let mut socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(DNS_SERVER).unwrap();

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut query = DnsUdpQuery::new(id, name, qtype);
    let mut arg = None;

    loop {
        match query.resume(arg.take()) {
            DnsUdpQueryResult::Ok { message } => return message,
            DnsUdpQueryResult::Io { input } => arg = Some(handle(&mut socket, input).unwrap()),
            DnsUdpQueryResult::Err { err } => panic!("DNS query failed: {err}"),
        }
    }
}
