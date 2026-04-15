//! Integration tests for RFC 3596 — IPv6 AAAA records.
//!
//! AAAA records are returned as [`DnsRecordData::Other`] by the core
//! decoder and decoded by [`io_discovery::rfc3596::aaaa::DnsAaaaData::decode`].

mod common;

use io_discovery::{
    rfc1035::types::{record_data::DnsRecordData, r#type::PTR},
    rfc3596::aaaa::{AAAA, DnsAaaaData},
};

/// AAAA record — IPv6 address (RFC 3596 §2.2).
///
/// example.com has had a stable AAAA record since 2016.
#[test]
fn aaaa_record() {
    let msg = common::udp_query("example.com", AAAA);
    assert!(!msg.answers.is_empty(), "expected AAAA records");

    for record in msg.answers {
        assert_eq!(
            record.r#type, AAAA,
            "expected type 28 (AAAA), got {}",
            record.r#type
        );

        match record.data {
            DnsRecordData::Other(data) => {
                let aaaa = DnsAaaaData::decode(&data).expect("AAAA data");
                assert!(
                    !aaaa.addr.is_unspecified(),
                    "decoded AAAA address is the unspecified address",
                );
            }
            data => {
                panic!("unexpected record data: {data:?}");
            }
        }
    }
}

/// AAAA reverse lookup — ip6.arpa PTR for a well-known address.
///
/// 2001:4860:4860::8888 is Google's IPv6 DNS server; its reverse PTR
/// resolves to dns.google.
#[test]
fn aaaa_reverse_ptr() {
    // Nibble-reversed form of 2001:4860:4860::8888
    let arpa = "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa";
    let msg = common::udp_query(arpa, PTR);
    assert!(
        !msg.answers.is_empty(),
        "expected PTR record for Google IPv6 DNS"
    );

    for record in msg.answers {
        match record.data {
            DnsRecordData::Ptr(name) => {
                assert!(
                    name.to_string().contains("dns.google"),
                    "expected dns.google, got {name}",
                );
            }
            data => {
                panic!("unexpected record data: {data:?}");
            }
        }
    }
}
