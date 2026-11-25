use thiserror::Error;

/// All errors surfaced to MCP clients. Messages are written to be actionable by a model.
#[derive(Debug, Error)]
pub enum MemError {
    #[error("no process attached; call `attach` first")]
    NotAttached,

    #[error("attached process {0} has exited; call `attach` again")]
    ProcessExited(u32),

    #[error("process not found: {0}")]
    ProcessNotFound(String),

    #[error("several processes match '{name}': pids {pids:?}; pass `pid` instead")]
    Ambiguous { name: String, pids: Vec<u32> },

    #[error("refusing to attach to protected system process '{0}'")]
    DeniedProcess(String),

    #[error("access denied to process {pid}: {hint}")]
    AccessDenied { pid: u32, hint: String },

    #[error("cannot read {size} bytes at {addr:#x}: {reason}")]
    Read { addr: u64, size: usize, reason: String },

    #[error("cannot write {size} bytes at {addr:#x}: {reason}")]
    Write { addr: u64, size: usize, reason: String },

    #[error("invalid address '{input}': {reason}")]
    BadAddress { input: String, reason: String },

    #[error("pointer chain broken at dereference #{step}: cannot read pointer at {addr:#x} ({reason}); trace so far: {trace}")]
    PointerChain { step: usize, addr: u64, reason: String, trace: String },

    #[error("invalid argument: {0}")]
    InvalidArg(String),

    #[error("not supported on this platform: {0}")]
    Unsupported(&'static str),

    #[error("os error: {0}")]
    Os(String),
}

pub type Result<T> = std::result::Result<T, MemError>;
