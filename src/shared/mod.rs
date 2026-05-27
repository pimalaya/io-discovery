pub mod dns;
#[cfg(any(feature = "autoconfig", feature = "pacc"))]
pub mod http;
#[cfg(feature = "client")]
pub mod pool;
