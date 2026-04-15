//! Integration tests for RFC 6698 — DANE / TLSA records.
//!
//! TLSA records (type 52) are returned as [`DnsRecordData::Other`] and
//! decoded by [`io_discovery::rfc6698::tlsa::DnsTlsaData::decode`].
//!
//! Test domain: `_443._tcp.fedoraproject.org`.
//! Fedora Project has published DANE TLSA records for their HTTPS
//! endpoint for several years and is a stable test target.

mod common;

use io_discovery::{
    rfc1035::types::record_data::DnsRecordData,
    rfc6698::tlsa::{DnsTlsaData, TYPE as TLSA},
};

/// TLSA record — certificate association (RFC 6698 §2).
#[test]
fn tlsa_record() {
    let name = DnsTlsaData::query_name(443, "tcp", "fedoraproject.org");
    let msg = common::udp_query(&name, TLSA);

    assert!(
        !msg.answers.is_empty(),
        "expected TLSA records — is fedoraproject.org still DANE-enabled?",
    );

    for record in msg.answers {
        assert_eq!(
            record.r#type, TLSA,
            "expected type 52 (TLSA), got {}",
            record.r#type
        );

        match record.data {
            DnsRecordData::Other(data) => {
                let tlsa = DnsTlsaData::decode(&data).expect("TLSA data");
                assert!(
                    !tlsa.data.is_empty(),
                    "TLSA association data should not be empty",
                );
            }
            data => {
                panic!("unexpected record data: {data:?}");
            }
        }
    }
}
