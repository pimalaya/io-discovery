//! Integration tests for RFC 2782 — SRV records.
//!
//! SRV records are returned as [`DnsRecordData::Other`] and decoded
//! by [`io_discovery::rfc2782::srv::DnsSrvData::decode`].

mod common;

use io_discovery::{
    rfc1035::types::record_data::DnsRecordData,
    rfc2782::srv::{DnsSrvData, SRV},
};

/// SRV record — service location (RFC 2782 §3).
///
/// _imaps._tcp.gmail.com → Gmail's IMAP-over-TLS servers. Google
/// maintains these records reliably.
#[test]
fn srv_record() {
    let msg = common::udp_query("_imaps._tcp.gmail.com", SRV);
    assert!(!msg.answers.is_empty(), "expected SRV records");

    for record in msg.answers {
        assert_eq!(
            record.r#type, SRV,
            "expected type 33 (SRV), got {}",
            record.r#type
        );

        match record.data {
            DnsRecordData::Other(data) => {
                let srv = DnsSrvData::decode(&data).expect("SRV data");
                assert!(srv.port > 0, "SRV port should be positive");

                let target = srv.target.to_string();
                assert!(
                    target.ends_with("gmail.com") || target.ends_with("google.com"),
                    "unexpected SRV target: {}",
                    srv.target,
                );
            }
            data => panic!("unexpected record data: {data:?}"),
        }
    }
}

/// SRV priority ordering — `priority_then_weight` sorts the records
/// so the lowest-priority group comes first.
#[test]
fn srv_priority_ordering() {
    let msg = common::udp_query("_imaps._tcp.gmail.com", SRV);
    assert!(!msg.answers.is_empty(), "expected SRV records");

    let mut records: Vec<DnsSrvData> = Vec::new();

    for record in msg.answers {
        match record.data {
            DnsRecordData::Other(data) => {
                records.push(DnsSrvData::decode(&data).expect("SRV data"));
            }
            data => {
                panic!("unexpected record data: {data:?}");
            }
        }
    }

    records.sort_by(DnsSrvData::priority_then_weight);

    for pair in records.windows(2) {
        assert!(
            pair[0].priority <= pair[1].priority,
            "records not sorted by priority: {} > {}",
            pair[0].priority,
            pair[1].priority,
        );
    }
}
