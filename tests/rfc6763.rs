//! Integration tests for RFC 6763 — DNS-Based Service Discovery.
//!
//! DNS-SD uses PTR records for enumeration and browsing, SRV + TXT
//! for instance resolution.  The helper functions [`parse_ptr`] and
//! [`parse_txt`] work on any [`DnsMessage`], so the network tests
//! below drive them with real DNS responses that are known to be
//! stable.

mod common;

use io_discovery::{
    rfc1035::types::{
        record_data::DnsRecordData,
        r#type::{PTR, TXT},
    },
    rfc6763::service::{parse_ptr, parse_txt},
};

/// `parse_ptr` collects PTR targets from a DNS response.
///
/// A reverse PTR lookup always returns at least one PTR record for a
/// well-known address such as 8.8.8.8.  We verify that [`parse_ptr`]
/// extracts the names correctly.
#[test]
fn parse_ptr_from_reverse_lookup() {
    let msg = common::udp_query("8.8.8.8.in-addr.arpa", PTR);
    assert!(!msg.answers.is_empty(), "expected PTR records");

    let targets = parse_ptr(&msg);
    assert!(!targets.is_empty(), "parse_ptr returned no targets");
    assert!(
        targets.iter().any(|t| t.contains("dns.google")),
        "expected dns.google in PTR targets, got: {targets:?}",
    );
}

/// `parse_txt` parses TXT record strings from a real DNS response.
///
/// `_dmarc.gmail.com` is a TXT-only name with a well-known `v=DMARC1`
/// entry, giving us a stable target for `parse_txt`.
#[test]
fn parse_txt_from_dmarc() {
    let msg = common::udp_query("_dmarc.gmail.com", TXT);
    assert!(!msg.answers.is_empty(), "expected TXT records");

    let mut txts: Vec<String> = Vec::new();

    for record in msg.answers {
        match record.data {
            DnsRecordData::Txt(txt) => txts.extend(txt),
            data => panic!("unexpected record data: {data:?}"),
        }
    }

    assert!(!txts.is_empty(), "no TXT strings found");

    let pairs = parse_txt(&txts);
    assert_eq!(
        pairs.len(),
        txts.len(),
        "pair count should equal string count"
    );

    // DMARC records contain "v=DMARC1…"; the value starts with "DMARC1".
    let has_dmarc = pairs
        .iter()
        .any(|(k, v)| k == "v" && v.as_deref().is_some_and(|s| s.starts_with("DMARC1")));
    assert!(
        has_dmarc,
        "expected v=DMARC1 in parsed pairs, got: {pairs:?}"
    );
}
