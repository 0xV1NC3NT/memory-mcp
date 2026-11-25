//! memory-mcp: local MCP server for reading, writing and scanning process memory.

pub mod address;
pub mod background;
pub mod binfmt;
pub mod disasm;
pub mod error;
pub mod format;
pub mod journal;
pub mod pattern;
pub mod pe;
pub mod platform;
pub mod pointer;
pub mod scan;
pub mod server;
pub mod structs;
pub mod value;

pub use error::{MemError, Result};
pub use server::MemoryServer;
