//! Integration tests for RFC 1035 record types.
//!
//! Tests A, NS, SOA, MX, TXT, and PTR records against a live DNS
//! resolver (Google Public DNS, 8.8.8.8).

mod common;

use io_discovery::rfc1035::types::{
    record_data::DnsRecordData,
    r#type::{A, MX, NS, PTR, SOA, TXT},
};

/// A record (IPv4 address, RFC 1035 §3.4.1).
#[test]
fn a_record() {
    let msg = common::udp_query("example.com", A);
    assert!(!msg.answers.is_empty(), "expected A records");

    for record in msg.answers {
        match record.data {
            DnsRecordData::A(_) => continue,
            data => panic!("unexpected record data: {data:?}"),
        }
    }
}

/// NS record (authoritative name server, RFC 1035 §3.3.11).
#[test]
fn ns_record() {
    let msg = common::udp_query("example.com", NS);
    assert!(!msg.answers.is_empty(), "expected NS records");

    for record in msg.answers {
        match record.data {
            DnsRecordData::Ns(_) => continue,
            data => panic!("unexpected record data: {data:?}"),
        }
    }
}

/// SOA record (start of authority, RFC 1035 §3.3.13).
#[test]
fn soa_record() {
    let msg = common::udp_query("example.com", SOA);
    assert_eq!(msg.answers.len(), 1, "expected exactly one SOA record");

    for record in msg.answers {
        match record.data {
            DnsRecordData::Soa {
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ..
            } => {
                assert!(serial > 0, "SOA serial should be positive");
                assert!(refresh > 0, "SOA refresh should be positive");
                assert!(retry > 0, "SOA retry should be positive");
                assert!(expire > 0, "SOA expire should be positive");
                assert!(minimum > 0, "SOA minimum should be positive");
            }
            data => panic!("unexpected record data: {data:?}"),
        }
    }
}

/// MX record (mail exchange, RFC 1035 §3.3.9).
#[test]
fn mx_record() {
    let msg = common::udp_query("gmail.com", MX);
    assert!(!msg.answers.is_empty(), "expected MX records");

    for record in msg.answers {
        match record.data {
            DnsRecordData::Mx {
                preference,
                exchange,
            } => {
                assert!(preference > 0, "MX preference should be positive");
                assert!(
                    exchange.to_string().ends_with("google.com"),
                    "unexpected MX exchange: {exchange}",
                );
            }
            data => {
                panic!("unexpected record data: {data:?}");
            }
        }
    }
}

/// TXT record (text strings, RFC 1035 §3.3.14).
#[test]
fn txt_record() {
    let msg = common::udp_query("example.com", TXT);
    assert!(!msg.answers.is_empty(), "expected TXT records");

    for record in msg.answers {
        match record.data {
            DnsRecordData::Txt(txt) => {
                assert!(!txt.is_empty(), "expected TXT record data");
            }
            data => {
                panic!("unexpected record data: {data:?}");
            }
        }
    }
}

/// PTR record — reverse DNS lookup (RFC 1035 §3.3.12).
///
/// 8.8.8.8.in-addr.arpa → dns.google.
#[test]
fn ptr_record_reverse_lookup() {
    let msg = common::udp_query("8.8.8.8.in-addr.arpa", PTR);
    assert!(!msg.answers.is_empty(), "expected PTR records");

    for record in msg.answers {
        match record.data {
            DnsRecordData::Ptr(name) => {
                assert!(
                    name.to_string().contains("dns.google"),
                    "expected dns.google, got {name}",
                );
            }
            data => panic!("unexpected record data: {data:?}"),
        }
    }
}
