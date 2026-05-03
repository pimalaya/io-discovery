#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate alloc;
#[cfg(any(feature = "client", feature = "cli"))]
extern crate std;

#[cfg(feature = "autoconfig")]
pub mod autoconfig;
#[cfg(feature = "pacc")]
pub mod pacc;
#[cfg(any(feature = "autoconfig", feature = "pacc"))]
pub mod shared;
