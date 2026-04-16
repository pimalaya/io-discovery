#![cfg_attr(not(feature = "cli"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

extern crate alloc;

#[cfg(feature = "autoconfig")]
pub mod autoconfig;
