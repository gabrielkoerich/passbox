//! One module per group of commands, called from `run` in main.

pub(crate) mod exec;
pub(crate) mod git;
#[cfg(feature = "host")]
pub(crate) mod import;
#[cfg(feature = "host")]
pub(crate) mod imports;
pub(crate) mod mcp;
#[cfg(feature = "host")]
pub(crate) mod phone;
pub(crate) mod plugins;
pub(crate) mod secrets;
pub(crate) mod setup;
pub(crate) mod skill;
pub(crate) mod tree;
