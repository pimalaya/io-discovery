#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate alloc;
#[cfg(feature = "cli")]
extern crate std;

#[cfg(feature = "autoconfig")]
pub mod autoconfig;
#[cfg(any(feature = "autoconfig", feature = "pacc"))]
pub mod dns_txt;
#[cfg(any(feature = "autoconfig", feature = "pacc"))]
pub mod http_get;
#[cfg(feature = "pacc")]
pub mod pacc;
