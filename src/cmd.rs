//! One module per group of commands, called from `run` in main.

pub(crate) mod exec;
pub(crate) mod git;
#[cfg(feature = "host")]
pub(crate) mod imports;
#[cfg(feature = "host")]
pub(crate) mod phone;
pub(crate) mod plugins;
pub(crate) mod secrets;
pub(crate) mod setup;
