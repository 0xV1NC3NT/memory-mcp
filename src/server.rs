//! MCP tool surface. Each tool is a thin wrapper: parse params → call core → JSON text.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rmcp::{
    ErrorData, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::address::{self, Offset};
use crate::background::{self, Freeze, FreezeMode, Target, Watch};
use crate::disasm::functions::{self as funcs, CodeCache, ModuleCode};
use crate::disasm::signature::{self as sigs, DataRef, SigOptions};
use crate::disasm::xrefs::{KIND_FILTERS, XrefKind};
use crate::disasm::{self, DecodeOptions, LineKind, Syntax, symbols::SymbolCache};
use crate::error::MemError;

type CoreResult<T> = crate::error::Result<T>;
use crate::format;
use crate::journal::{Journal, NewWrite};
use crate::pattern::{self, Pattern, Scope};
use crate::scan::{self, Cond, FloatMode, Generation, ScanSpec, ScanType};
use crate::platform::{self, Process, RegionKind, RegionState};
use crate::pointer::{self, Chain, PtrScanOptions, PtrScanStats};
use crate::structs::{self, FieldDef, Registry, StructDef};
use crate::value::{self, Scalar, ValueType};

const MAX_READ_BYTES: usize = 64 * 1024;
const MAX_READ_COUNT: usize = 4096;
const MAX_WRITE_BYTES: usize = 64 * 1024;
const MAX_STRUCT_COUNT: usize = 256;
const MAX_AOB_LIMIT: usize = 10_000;
const MAX_SCAN_SESSIONS: usize = 16;
const DEFAULT_SCAN_MEMORY_MB: u64 = 512;
const PREVIEW: usize = 20;
const MAX_BACKGROUND: usize = 64;
const MAX_PTR_SCANS: usize = 8;

const INSTRUCTIONS: &str = "Local process memory tools. Workflow: list_processes → attach → list_modules / list_regions → resolve_address / read_value / read_bytes. Address expressions: 0x1A2B | 1A2Bh | #6699 (decimal) | bare hex | game.exe+0x10 | \"my mod.dll\"+10 | kernel32.dll!CreateFileW | mod.dll!#12 (ordinal) | [[game.exe+0x10]+0x20]+8 (dereference) | + - * ( ). Pointer chains can also be given as `offsets` (for each: addr = [addr] + offset). For 32-bit targets pointers are 4 bytes and only addresses below 4 GiB are valid. Writes (write_value / write_bytes) lift page protection temporarily, verify by reading back and are journaled: \
undo_write restores the original bytes (refuses if memory changed since, unless force=true); list_writes shows the journal. \
Struct templates: define_struct (fields with types incl. nested structs, arrays, *Ptr; offsets optional, \
C-like alignment by target bitness), read_struct (follows pointer fields), write_struct (fields by path like pos.x / items[2]). \
Signatures: aob_scan finds byte patterns (IDA `48 8B ?? 05`, CE `*`, nibbles `4?`, `\\x48\\x8B`+mask `xx?`, \
raw hex, str:\"text\", wstr:\"text\") in a module, .section or the whole process; aob_resolve turns a unique match into an \
address (+offset, rip-relative, abs32 or pointer) and returns an equivalent expression. In expressions: \
sig(\"pattern\", module[, \".section\"]), rip(addr, disp_offset=3, insn_len=7), abs32(addr, offset); \
numbers inside function arguments are hex like everywhere else. \
Value scans (Cheat Engine style): scan_start (exact/range/bigger/smaller/not/unknown; numeric types; default scope = \
writable non-mapped memory) → change the value in the program → scan_next (changed/unchanged/increased/decreased/\
increased_by/decreased_by/exact/...) until few candidates remain → scan_results → write_value. Float comparisons are \
rounded to the decimals you type (float_mode). \
Background: freeze_value keeps a value fixed (modes exact / no_decrease / no_increase), watch_value records every \
change with timestamps (read with watch_read since=next_since); pointer-chain expressions are re-resolved each tick. \
They stop on unfreeze/unwatch, detach/attach, or when the process exits. \
Pointer scan: pointer_scan finds static chains module+base → offsets → target (reverse search up to max_depth with \
max_offset per level); after restarting the game, attach again, find the value anew and call pointer_rescan with the \
new target to keep only chains that still work. Chains are usable directly as `address` + `offsets`. \
Disassembly: disassemble(address, count | size | until_ret, syntax intel|masm|nasm|att) lists instructions with \
module+offset, bytes, symbolized targets (exports like kernel32.dll!Sleep) and `-> import` comments for indirect calls. \
Functions: function_info / disassemble_function find the function containing an address (x64 .pdata exact; \
otherwise known starts — call targets, exports — or int3 padding, end by control-flow traversal); list_functions \
lists a module's functions. \
Cross-references: find_xrefs(target) lists instructions that call/jump to, read, write or take the address of \
a target (also through pointer slots such as the import table), with the containing function. \
Signatures: make_signature(address) builds the shortest unique AOB for code (addresses/branches wildcarded) and \
returns ready expressions: sig(...)+off for the instruction and rip(...)/abs32(...) for the data it references; for a \
data address it signs a referencing instruction. Use these expressions to find the same place after game updates. \
All addresses in output are hex. Lists are paginated (offset/limit, `has_more`).";

#[derive(Clone)]
pub struct MemoryServer {
    attached: Arc<Mutex<Option<Process>>>,
    journal: Arc<Mutex<Journal>>,
    structs: Arc<Mutex<Registry>>,
    scans: Arc<Mutex<HashMap<u64, Arc<Mutex<ScanSession>>>>>,
    next_scan_id: Arc<AtomicU64>,
    freezes: Arc<Mutex<HashMap<u64, Freeze>>>,
    watches: Arc<Mutex<HashMap<u64, Watch>>>,
    next_bg_id: Arc<AtomicU64>,
    ptr_scans: Arc<Mutex<HashMap<u64, PtrSession>>>,
    symbols: Arc<Mutex<SymbolCache>>,
    code: Arc<CodeCache>,
    next_ptr_id: Arc<AtomicU64>,
    tool_router: ToolRouter<Self>,
}

impl Default for MemoryServer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- parameters ----------

// `serde_json::Value` fields would get the boolean JSON schema `true` ("anything"), which is valid
// JSON Schema but rejected by some MCP clients (e.g. opencode). Give them explicit type lists.

fn schema_write_value(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": ["number", "string", "boolean", "array"],
        "items": { "type": ["number", "string", "boolean"] }
    })
}

fn schema_scalar_value(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({ "type": ["number", "string"] })
}

fn schema_field_values(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "additionalProperties": {
            "type": ["number", "string", "boolean", "array"],
            "items": { "type": ["number", "string", "boolean"] }
        }
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListProcessesParams {
    /// Case-insensitive substring of the executable name, or an exact pid.
    pub filter: Option<String>,
    pub offset: Option<usize>,
    /// Page size (default 100, max 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AttachParams {
    /// Process id. Takes precedence over `name`.
    pub pid: Option<u32>,
    /// Executable name, e.g. `game.exe` or `game` (case-insensitive).
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListModulesParams {
    /// Case-insensitive substring of the module name.
    pub filter: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListRegionsParams {
    /// Required protection flags, any combination of r/w/x, e.g. `rw` or `x`.
    pub protection: Option<String>,
    /// Region kind: `image`, `mapped` or `private`.
    pub kind: Option<String>,
    /// Only regions belonging to this module (case-insensitive name).
    pub module: Option<String>,
    /// Include reserved (uncommitted) regions. Default false.
    pub include_reserved: Option<bool>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadValueParams {
    /// Address expression: `0x7FF6A1B2C3D0`, `game.exe+0x1A2B`, `[[game.exe+0x10]+0x20]+8`,
    /// `kernel32.dll!CreateFileW`, `#1234` (decimal). Bare numbers are hex.
    pub address: String,
    /// Optional pointer chain applied after `address` (Cheat Engine semantics: for each offset,
    /// addr = [addr] + offset). JSON numbers are decimal; strings are expressions (hex by default), e.g. ["0x18", -8].
    pub offsets: Option<Vec<Offset>>,
    /// Value type: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 bool ptr bytes utf8 utf16
    /// (aliases: int, float, double, string, wstring, pointer ...).
    #[serde(rename = "type")]
    pub value_type: String,
    /// Number of consecutive elements to read (default 1, max 4096). Ignored for strings.
    pub count: Option<usize>,
    /// For `bytes`: number of bytes (required). For `utf8`: max bytes, for `utf16`: max chars (default 256).
    pub length: Option<usize>,
    /// Interpret as big-endian. Default false.
    pub big_endian: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadBytesParams {
    /// Address expression: `0x7FF6A1B2C3D0`, `game.exe+0x1A2B`, `[[game.exe+0x10]+0x20]+8`,
    /// `kernel32.dll!CreateFileW`, `#1234` (decimal). Bare numbers are hex.
    pub address: String,
    /// Optional pointer chain applied after `address` (Cheat Engine semantics: for each offset,
    /// addr = [addr] + offset). JSON numbers are decimal; strings are expressions (hex by default), e.g. ["0x18", -8].
    pub offsets: Option<Vec<Offset>>,
    /// Number of bytes (max 65536).
    pub size: usize,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveAddressParams {
    /// Address expression: `0x7FF6A1B2C3D0`, `game.exe+0x1A2B`, `[[game.exe+0x10]+0x20]+8`,
    /// `kernel32.dll!CreateFileW`, `#1234` (decimal). Bare numbers are hex.
    pub address: String,
    /// Optional pointer chain applied after `address` (Cheat Engine semantics: for each offset,
    /// addr = [addr] + offset). JSON numbers are decimal; strings are expressions (hex by default), e.g. ["0x18", -8].
    pub offsets: Option<Vec<Offset>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteValueParams {
    /// Address expression: `0x7FF6A1B2C3D0`, `game.exe+0x1A2B`, `[[game.exe+0x10]+0x20]+8`,
    /// `kernel32.dll!CreateFileW`, `#1234` (decimal). Bare numbers are hex.
    pub address: String,
    /// Optional pointer chain applied after `address` (for each offset: addr = [addr] + offset).
    /// JSON numbers are decimal; strings are expressions (hex by default).
    pub offsets: Option<Vec<Offset>>,
    /// Value type: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 bool ptr bytes utf8 utf16 (aliases as in read_value).
    #[serde(rename = "type")]
    pub value_type: String,
    /// Value to write. Integers: number or string ("-5", "0xFF"; signed or unsigned range).
    /// Floats: number or string. bool: true/false/0/1. ptr: number or address expression string
    /// (e.g. "game.exe+0x10"). bytes: hex string. utf8/utf16: text. A JSON array writes consecutive elements.
    #[schemars(schema_with = "schema_write_value")]
    pub value: Value,
    /// Big-endian encoding. Default false.
    pub big_endian: Option<bool>,
    /// For utf8/utf16: append a NUL terminator. Default true.
    pub null_terminate: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteBytesParams {
    /// Address expression: `0x7FF6A1B2C3D0`, `game.exe+0x1A2B`, `[[game.exe+0x10]+0x20]+8`,
    /// `kernel32.dll!CreateFileW`, `#1234` (decimal). Bare numbers are hex.
    pub address: String,
    /// Optional pointer chain applied after `address` (for each offset: addr = [addr] + offset).
    /// JSON numbers are decimal; strings are expressions (hex by default).
    pub offsets: Option<Vec<Offset>>,
    /// Bytes to write as hex: "DE AD BE EF", "DEADBEEF", "\\xDE\\xAD" or "0xDE, 0xAD" (max 65536 bytes).
    pub bytes: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UndoWriteParams {
    /// Write id from write_value / write_bytes / list_writes. Default: the latest active write in the attached process.
    pub id: Option<u64>,
    /// Restore even if the memory changed since the write (e.g. the program overwrote it). Default false.
    pub force: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListWritesParams {
    /// Include writes to other (previously attached) processes. Default false.
    pub all_processes: Option<bool>,
    /// Include writes that were already undone. Default true.
    pub include_undone: Option<bool>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DefineStructParams {
    /// Template name (letters, digits, underscore). Redefining replaces the template.
    pub name: String,
    /// Fields in order. Offsets are optional (auto layout with natural alignment).
    pub fields: Vec<FieldDef>,
    /// No padding between auto-placed fields. Default false.
    pub packed: Option<bool>,
    /// Explicit total size in bytes (default: computed).
    pub size: Option<u64>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListStructsParams {
    /// Show one template with its full definition and layout.
    pub name: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteStructParams {
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReadStructParams {
    /// Address expression of the struct start.
    pub address: String,
    /// Optional pointer chain applied after `address` (for each offset: addr = [addr] + offset).
    pub offsets: Option<Vec<Offset>>,
    /// Template name (see define_struct / list_structs). Alternatively pass inline `fields`.
    #[serde(rename = "struct")]
    pub r#struct: Option<String>,
    /// Inline field list for a one-off read (same format as define_struct).
    pub fields: Option<Vec<FieldDef>>,
    /// For inline fields: packed layout.
    pub packed: Option<bool>,
    /// Read an array of consecutive structs (default 1, max 256).
    pub count: Option<usize>,
    /// How many levels of *Struct pointer fields to follow (default 1, max 8; 0 = do not follow).
    pub depth: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WriteStructParams {
    /// Address expression of the struct start.
    pub address: String,
    pub offsets: Option<Vec<Offset>>,
    /// Template name. Alternatively pass inline `fields`.
    #[serde(rename = "struct")]
    pub r#struct: Option<String>,
    pub fields: Option<Vec<FieldDef>>,
    pub packed: Option<bool>,
    /// Field paths → values, e.g. {"health": 100, "pos.x": 1.5, "items[2]": 7, "name": "Bob"}.
    /// Values follow write_value rules; each field is a separate journaled write.
    #[schemars(schema_with = "schema_field_values")]
    pub values: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AobScanParams {
    /// Pattern: `48 8B ?? ?? 05`, `48 8B * * 05`, `4? 8B ?5`, `488B????05`, `\\x48\\x8B\\x00` (+ mask),
    /// `str:"text"`, `wstr:"text"`.
    pub pattern: String,
    /// Code-style mask, one char per byte: `x` exact, `?` wildcard (e.g. `xx??x`).
    pub mask: Option<String>,
    /// Limit the scan to this module (name, e.g. `game.exe` or `game`).
    pub module: Option<String>,
    /// PE section of `module`, e.g. `.text`, `.rdata`, `.data`.
    pub section: Option<String>,
    /// Range start (address expression), inclusive.
    pub start: Option<String>,
    /// Range end (address expression), exclusive.
    pub end: Option<String>,
    /// Required protection flags, e.g. `x` (code only) or `rw`.
    pub protection: Option<String>,
    /// Only report matches at addresses divisible by this (default 1).
    pub alignment: Option<u64>,
    /// Maximum matches to return (default 100, max 10000).
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AobResolveParams {
    /// Pattern (same notations as aob_scan).
    pub pattern: String,
    pub mask: Option<String>,
    pub module: Option<String>,
    pub section: Option<String>,
    pub protection: Option<String>,
    /// Which match to use (0-based). Default: the pattern must match exactly once.
    pub index: Option<usize>,
    /// Added to the match address before `mode` is applied (may be negative). Default 0.
    pub offset: Option<i64>,
    /// `address` (default): match + offset. `rip`: relative target = addr + insn_len + i32 at (addr + disp_offset).
    /// `abs32`: u32 stored at addr + disp_offset. `ptr`: pointer stored at addr.
    pub mode: Option<String>,
    /// For rip (default 3) / abs32 (default 0).
    pub disp_offset: Option<u64>,
    /// For rip: instruction length (default 7).
    pub insn_len: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanStartParams {
    /// Numeric type: i8 u8 i16 u16 i32 u32 i64 u64 f32 f64 bool ptr (aliases: int, float, double ...).
    #[serde(rename = "type")]
    pub value_type: String,
    /// exact (default when `value` is given), not, range (value..=value2), bigger, smaller,
    /// unknown (snapshot everything; narrow later with changed/unchanged/increased/decreased).
    pub condition: Option<String>,
    /// Value: number or string ("-5", "0xFF", "1.25").
    #[serde(default)]
    #[schemars(schema_with = "schema_scalar_value")]
    pub value: Option<Value>,
    /// Upper bound for `range`.
    #[serde(default)]
    #[schemars(schema_with = "schema_scalar_value")]
    pub value2: Option<Value>,
    /// Limit to a module (and optionally a PE `section`).
    pub module: Option<String>,
    pub section: Option<String>,
    /// Address range (expressions); `end` is exclusive.
    pub start: Option<String>,
    pub end: Option<String>,
    /// Required protection flags. Default `w` (writable memory); pass "" for all readable memory.
    pub protection: Option<String>,
    /// Include memory-mapped files. Default false.
    pub include_mapped: Option<bool>,
    /// Only addresses divisible by this. Default: natural alignment of the type, at most 4. Use 1 for unaligned.
    pub alignment: Option<u64>,
    /// Floats: rounded (default; to the decimals you typed), truncated, exact.
    pub float_mode: Option<String>,
    /// Floats: absolute tolerance |a - b| <= tolerance (overrides float_mode).
    pub tolerance: Option<f64>,
    /// RAM budget for candidates in MiB (default 512); the rest goes to a temporary file.
    pub max_memory_mb: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanNextParams {
    pub scan_id: u64,
    /// changed, unchanged, increased, decreased, increased_by, decreased_by, exact, not, range, bigger, smaller.
    pub condition: String,
    /// Value for exact/not/range/bigger/smaller/increased_by/decreased_by: number or string.
    #[serde(default)]
    #[schemars(schema_with = "schema_scalar_value")]
    pub value: Option<Value>,
    /// Upper bound for `range`.
    #[serde(default)]
    #[schemars(schema_with = "schema_scalar_value")]
    pub value2: Option<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanResultsParams {
    pub scan_id: u64,
    pub offset: Option<u64>,
    /// Page size (default 50, max 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScanCloseParams {
    pub scan_id: u64,
}

pub struct ScanSession {
    id: u64,
    pid: u32,
    spec: ScanSpec,
    scope: String,
    budget: u64,
    history: Vec<Value>,
    generation: Generation,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FreezeParams {
    /// Address expression (see resolve_address).
    pub address: String,
    /// Optional pointer chain applied after `address` (for each offset: addr = [addr] + offset).
    pub offsets: Option<Vec<Offset>>,
    /// Value type (as in write_value).
    #[serde(rename = "type")]
    pub value_type: String,
    /// Value to hold (write_value rules). Default: the current value.
    #[serde(default)]
    #[schemars(schema_with = "schema_write_value")]
    pub value: Option<Value>,
    /// For bytes/strings without `value`: number of bytes (utf16: chars) to hold.
    pub length: Option<usize>,
    /// exact (default): restore on any change; no_decrease: only restore when it drops below the value;
    /// no_increase: only restore when it rises above the value.
    pub mode: Option<String>,
    /// Check/restore period in ms (default 100, 5..=60000).
    pub interval_ms: Option<u64>,
    /// Re-evaluate the address every tick (default: true for [..] dereferences and offsets).
    pub re_resolve: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnfreezeParams {
    pub freeze_id: Option<u64>,
    /// Stop all freezes.
    pub all: Option<bool>,
    /// Write back the value that was there when the freeze started. Default false.
    pub restore: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WatchParams {
    /// Address expression (see resolve_address).
    pub address: String,
    /// Optional pointer chain applied after `address` (for each offset: addr = [addr] + offset).
    pub offsets: Option<Vec<Offset>>,
    /// Value type (as in read_value).
    #[serde(rename = "type")]
    pub value_type: String,
    /// For bytes (required) / strings.
    pub length: Option<usize>,
    /// Sampling period in ms (default 100, 5..=60000). Changes shorter than this can be missed.
    pub interval_ms: Option<u64>,
    /// Ring buffer size (default 1000, max 100000); older changes are dropped.
    pub max_events: Option<usize>,
    /// Re-evaluate the address every tick (default: true for [..] dereferences and offsets).
    pub re_resolve: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct WatchReadParams {
    pub watch_id: u64,
    /// Return changes with seq >= since (use `next_since` from the previous call). Default 0.
    pub since: Option<u64>,
    /// Max changes to return (default 200, max 5000).
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UnwatchParams {
    pub watch_id: Option<u64>,
    pub all: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PointerScanParams {
    /// Address expression of the value to find pointers to (e.g. a scan_results address).
    pub target: String,
    pub offsets: Option<Vec<Offset>>,
    /// Maximum chain length (default 4, max 7).
    pub max_depth: Option<usize>,
    /// Maximum offset per level: number (decimal) or string (hex, e.g. "0x1000"). Default 0x1000.
    pub max_offset: Option<crate::structs::FieldOffset>,
    /// Allowed modules for the static base (default: any module).
    pub modules: Option<Vec<String>>,
    /// Stop after this many chains (default 1000, max 100000).
    pub max_results: Option<usize>,
    /// Stop after visiting this many addresses (default 1000000, max 20000000).
    pub max_nodes: Option<usize>,
    /// Also index memory-mapped files. Default false.
    pub include_mapped: Option<bool>,
    /// Alignment of stored pointers (default: pointer size; 1 for packed structures — slower).
    pub alignment: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PointerResultsParams {
    pub ptr_scan_id: u64,
    pub offset: Option<usize>,
    /// Page size (default 50, max 1000).
    pub limit: Option<usize>,
    /// Re-evaluate each chain in the attached process. Default true.
    pub verify: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PointerRescanParams {
    pub ptr_scan_id: u64,
    /// New target address expression (required after a restart or if the value moved).
    /// Default: the previous target (same process only).
    pub target: Option<String>,
    pub offsets: Option<Vec<Offset>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PointerCloseParams {
    pub ptr_scan_id: u64,
}

pub struct PtrSession {
    id: u64,
    pid: u32,
    process_name: String,
    target: u64,
    chains: Vec<Chain>,
    stats: PtrScanStats,
    history: Vec<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisassembleParams {
    /// Address expression to start at (e.g. `game.exe+0x1A2B`, `kernel32.dll!Sleep`, `[[game.exe+0x10]]`).
    pub address: String,
    pub offsets: Option<Vec<Offset>>,
    /// Maximum number of instructions (default 30, max 2000).
    pub count: Option<usize>,
    /// Maximum number of bytes to decode (default: enough for `count`; max 65536).
    pub size: Option<usize>,
    /// Stop after the first `ret`. Default false.
    pub until_ret: Option<bool>,
    /// intel (default), masm, nasm or att.
    pub syntax: Option<String>,
    /// Show instruction bytes in the listing. Default true.
    pub show_bytes: Option<bool>,
    /// Also return structured per-instruction data (flow, branch target, memory operand). Default false.
    pub details: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FunctionParams {
    /// Any address inside the function (address expression).
    pub address: String,
    pub offsets: Option<Vec<Offset>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DisassembleFunctionParams {
    /// Any address inside the function (address expression).
    pub address: String,
    pub offsets: Option<Vec<Offset>>,
    /// intel (default), masm, nasm or att.
    pub syntax: Option<String>,
    /// Show instruction bytes. Default true.
    pub show_bytes: Option<bool>,
    /// Also return structured per-instruction data. Default false.
    pub details: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListFunctionsParams {
    /// Module name, e.g. `game.exe`.
    pub module: String,
    /// Only functions whose symbol contains this text (case-insensitive), e.g. an export name.
    pub filter: Option<String>,
    pub offset: Option<usize>,
    /// Page size (default 100, max 1000).
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FindXrefsParams {
    /// Target address expression (a function, a static variable, an export like `kernel32.dll!Sleep`).
    pub target: String,
    pub offsets: Option<Vec<Offset>>,
    /// Size of the target range in bytes (default 1) — e.g. 4 for an int, a struct size for any field.
    pub size: Option<u64>,
    /// any (default), call, jump, code (call+jump), read, write, access (read+write), address.
    pub kind: Option<String>,
    /// Modules whose code is searched (default: the target's module and the main executable; ["*"] = all).
    pub modules: Option<Vec<String>>,
    /// Also find references through pointer slots holding the target (import table, vtables). Default true.
    pub via_pointers: Option<bool>,
    pub offset: Option<usize>,
    /// Page size (default 100, max 1000).
    pub limit: Option<usize>,
    /// intel (default), masm, nasm or att.
    pub syntax: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MakeSignatureParams {
    /// Code address to sign, or a static data address (then a referencing instruction is signed).
    pub address: String,
    pub offsets: Option<Vec<Offset>>,
    /// Module the pattern must be unique in (default: the module containing the address).
    pub module: Option<String>,
    /// Minimum number of instruction bytes covered before uniqueness is checked (default 8; trailing
    /// wildcards are trimmed afterwards, so the final pattern can be slightly shorter).
    pub min_len: Option<usize>,
    /// Maximum pattern length in bytes (default 64, max 256).
    pub max_len: Option<usize>,
    /// Also wildcard struct offsets `[reg+disp]` (more robust to layout changes, longer patterns). Default false.
    pub wildcard_offsets: Option<bool>,
    /// Wildcard all immediates, not only address-like ones. Default false.
    pub wildcard_immediates: Option<bool>,
    /// How many earlier instructions may start the pattern when the target itself is not unique enough (default 8).
    pub max_back: Option<usize>,
}

/// Persistence locations; `None` keeps the data in memory only.
#[derive(Debug, Default, Clone)]
pub struct ServerOptions {
    pub journal: Option<PathBuf>,
    pub structs: Option<PathBuf>,
}

// ---------- helpers ----------

fn ok(v: Value) -> std::result::Result<CallToolResult, ErrorData> {
    let text = serde_json::to_string_pretty(&v).unwrap_or_else(|e| e.to_string());
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

/// Runs a potentially long, blocking operation on tokio's blocking pool.
async fn blocking<F>(f: F) -> std::result::Result<CallToolResult, ErrorData>
where
    F: FnOnce() -> CoreResult<Value> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => respond(r),
        Err(e) => Err(ErrorData::internal_error(format!("scan task failed: {e}"), None)),
    }
}

fn respond(r: CoreResult<Value>) -> std::result::Result<CallToolResult, ErrorData> {
    match r {
        Ok(v) => ok(v),
        Err(e) => Ok(CallToolResult::error(vec![ContentBlock::text(format!("error: {e}"))])),
    }
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// Lower-cased process name without the host's executable suffix (`.exe` on Windows).
fn strip_exe(s: &str) -> String {
    let l = s.to_ascii_lowercase();
    let suffix = std::env::consts::EXE_SUFFIX;
    match l.strip_suffix(suffix) {
        Some(stem) if !suffix.is_empty() => stem.to_string(),
        _ => l,
    }
}

impl MemoryServer {
    /// In-memory journal and struct registry (nothing is persisted).
    pub fn new() -> Self {
        Self::with_options(ServerOptions::default())
    }

    /// Server whose write journal is also appended to `file` (JSONL).
    pub fn with_journal(file: Option<PathBuf>) -> Self {
        Self::with_options(ServerOptions { journal: file, structs: None })
    }

    pub fn with_options(opts: ServerOptions) -> Self {
        let (registry, warning) = Registry::load(opts.structs);
        if let Some(w) = warning {
            tracing::warn!("{w}");
        }
        Self {
            attached: Arc::new(Mutex::new(None)),
            journal: Arc::new(Mutex::new(Journal::new(opts.journal))),
            structs: Arc::new(Mutex::new(registry)),
            scans: Arc::new(Mutex::new(HashMap::new())),
            next_scan_id: Arc::new(AtomicU64::new(1)),
            freezes: Arc::new(Mutex::new(HashMap::new())),
            watches: Arc::new(Mutex::new(HashMap::new())),
            next_bg_id: Arc::new(AtomicU64::new(1)),
            ptr_scans: Arc::new(Mutex::new(HashMap::new())),
            symbols: Arc::new(Mutex::new(SymbolCache::default())),
            code: Arc::new(CodeCache::default()),
            next_ptr_id: Arc::new(AtomicU64::new(1)),
            tool_router: Self::tool_router(),
        }
    }

    /// Currently attached process; errors if none or it has exited.
    pub fn process(&self) -> CoreResult<Process> {
        let guard = self.attached.lock().unwrap();
        let p = guard.as_ref().ok_or(MemError::NotAttached)?.clone();
        if !p.is_alive() {
            return Err(MemError::ProcessExited(p.pid()));
        }
        Ok(p)
    }

    fn resolve(&self, p: &Process, input: &str, offsets: &Option<Vec<Offset>>) -> CoreResult<u64> {
        Ok(address::resolve(p.as_ref(), input, offsets.as_deref().unwrap_or(&[]))?.address)
    }

    fn process_info_value(p: &Process) -> Value {
        let ps = p.pointer_size();
        let modules = p.modules().unwrap_or_default();
        let main = modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(p.name()))
            .or_else(|| modules.first());
        json!({
            "pid": p.pid(),
            "name": p.name(),
            "path": p.image_path(),
            "arch": p.arch(),
            "bits": ps * 8,
            "pointer_size": ps,
            "can_write": p.can_write(),
            "main_module": main.map(|m| json!({
                "name": m.name,
                "base": format::addr(m.base, ps),
                "size": format::size(m.size),
            })),
            "module_count": modules.len(),
        })
    }

    // ---- core implementations (also used by tests) ----

    pub fn do_list_processes(&self, p: ListProcessesParams) -> CoreResult<Value> {
        let mut list = platform::list_processes()?;
        if let Some(f) = p.filter.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
            let pid = f.parse::<u32>().ok();
            list.retain(|e| Some(e.pid) == pid || contains_ci(&e.name, f));
        }
        list.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()).then(a.pid.cmp(&b.pid)));
        Ok(format::page(&list, p.offset, p.limit))
    }

    pub fn do_attach(&self, p: AttachParams) -> CoreResult<Value> {
        let pid = match (p.pid, p.name.as_deref()) {
            (Some(pid), _) => pid,
            (None, Some(name)) => {
                let all = platform::list_processes()?;
                let want = strip_exe(name);
                let exact: Vec<u32> = all.iter().filter(|e| strip_exe(&e.name) == want).map(|e| e.pid).collect();
                let cands = if exact.is_empty() {
                    all.iter().filter(|e| contains_ci(&e.name, name)).map(|e| e.pid).collect()
                } else {
                    exact
                };
                match cands.as_slice() {
                    [] => return Err(MemError::ProcessNotFound(name.into())),
                    [one] => *one,
                    many => return Err(MemError::Ambiguous { name: name.into(), pids: many.to_vec() }),
                }
            }
            (None, None) => return Err(MemError::InvalidArg("pass `pid` or `name`".into())),
        };
        let proc = platform::open_process(pid)?;
        let info = Self::process_info_value(&proc);
        let stopped = self.stop_all_background("attached to another process");
        *self.attached.lock().unwrap() = Some(proc);
        let mut out = json!({ "attached": info });
        if stopped != (0, 0) {
            out["stopped_background"] = json!({ "freezes": stopped.0, "watches": stopped.1 });
        }
        Ok(out)
    }

    pub fn do_detach(&self) -> CoreResult<Value> {
        let stopped = self.stop_all_background("detached");
        let prev = self.attached.lock().unwrap().take();
        Ok(json!({
            "detached": prev.map(|p| p.pid()),
            "stopped_background": { "freezes": stopped.0, "watches": stopped.1 },
        }))
    }

    pub fn do_process_info(&self) -> CoreResult<Value> {
        let p = self.process()?;
        Ok(Self::process_info_value(&p))
    }

    pub fn do_list_modules(&self, prm: ListModulesParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let mut mods = p.modules()?;
        if let Some(f) = prm.filter.as_deref().filter(|f| !f.is_empty()) {
            mods.retain(|m| contains_ci(&m.name, f));
        }
        let items: Vec<Value> = mods
            .iter()
            .map(|m| {
                json!({
                    "name": m.name,
                    "base": format::addr(m.base, ps),
                    "end": format::addr(m.base + m.size, ps),
                    "size": format::size(m.size),
                    "arch": m.arch,
                    "path": m.path,
                })
            })
            .collect();
        Ok(format::page(&items, prm.offset, prm.limit))
    }

    pub fn do_list_regions(&self, prm: ListRegionsParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let modules = p.modules().unwrap_or_default();
        let kind = match prm.kind.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None | Some("") => None,
            Some("image") => Some(RegionKind::Image),
            Some("mapped") => Some(RegionKind::Mapped),
            Some("private") => Some(RegionKind::Private),
            Some(k) => return Err(MemError::InvalidArg(format!("unknown kind '{k}' (image|mapped|private)"))),
        };
        let module = match prm.module.as_deref().filter(|m| !m.is_empty()) {
            None => None,
            Some(name) => Some(
                modules
                    .iter()
                    .find(|m| m.name.eq_ignore_ascii_case(name) || strip_exe(&m.name) == strip_exe(name))
                    .ok_or_else(|| MemError::InvalidArg(format!("module '{name}' not found")))?
                    .clone(),
            ),
        };
        let include_reserved = prm.include_reserved.unwrap_or(false);
        let regions: Vec<Value> = p
            .regions()?
            .into_iter()
            .filter(|r| include_reserved || r.state == RegionState::Commit)
            .filter(|r| prm.protection.as_deref().is_none_or(|f| r.protect.matches(f)))
            .filter(|r| kind.is_none_or(|k| r.kind == k))
            .filter(|r| module.as_ref().is_none_or(|m| m.contains(r.base)))
            .map(|r| {
                let owner = modules.iter().find(|m| m.contains(r.base)).map(|m| m.name.clone());
                json!({
                    "base": format::addr(r.base, ps),
                    "end": format::addr(r.end(), ps),
                    "size": format::size(r.size),
                    "protect": r.protect.short(),
                    "state": r.state,
                    "kind": r.kind,
                    "module": owner,
                })
            })
            .collect();
        Ok(format::page(&regions, prm.offset, prm.limit))
    }

    pub fn do_read_value(&self, prm: ReadValueParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let ty = ValueType::parse(&prm.value_type, prm.length)?;
        let is_string = matches!(ty, ValueType::Utf8(_) | ValueType::Utf16(_));
        let count = if is_string { 1 } else { prm.count.unwrap_or(1) };
        if count == 0 || count > MAX_READ_COUNT {
            return Err(MemError::InvalidArg(format!("count must be 1..={MAX_READ_COUNT}")));
        }
        let elem = ty.size(ps);
        let total = elem * count;
        if total > MAX_READ_BYTES {
            return Err(MemError::InvalidArg(format!("read of {total} bytes exceeds {MAX_READ_BYTES}")));
        }
        let be = prm.big_endian.unwrap_or(false);

        let buf: Vec<u8> = if is_string {
            // Strings may run up to an unreadable page; take what is readable from the start.
            let partial = p.read_partial(addr, total);
            let n = partial.iter().take_while(|b| b.is_some()).count();
            if n == 0 {
                return Err(MemError::Read { addr, size: total, reason: p.explain_unreadable(addr) });
            }
            partial[..n].iter().map(|b| b.unwrap()).collect()
        } else {
            let mut b = vec![0u8; total];
            p.read(addr, &mut b)?;
            b
        };

        if is_string {
            let mut v = value::decode(ty, &buf, ps, be);
            v["address"] = json!(format::addr(addr, ps));
            v["type"] = json!(ty.name());
            return Ok(v);
        }
        let values: Vec<Value> = buf
            .chunks_exact(elem)
            .enumerate()
            .map(|(i, chunk)| {
                let mut v = value::decode(ty, chunk, ps, be);
                v["address"] = json!(format::addr(addr + (i * elem) as u64, ps));
                v
            })
            .collect();
        if count == 1 {
            let mut v = values.into_iter().next().unwrap();
            v["type"] = json!(ty.name());
            Ok(v)
        } else {
            Ok(json!({ "type": ty.name(), "count": count, "values": values }))
        }
    }

    pub fn do_resolve_address(&self, prm: ResolveAddressParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let r = address::resolve(p.as_ref(), &prm.address, prm.offsets.as_deref().unwrap_or(&[]))?;
        let modules = p.modules().unwrap_or_default();
        let region = p.query(r.address);
        Ok(json!({
            "address": format::addr(r.address, ps),
            "symbol": address::symbolize(&modules, r.address),
            "region": region.map(|reg| json!({
                "base": format::addr(reg.base, ps),
                "protect": reg.protect.short(),
                "state": reg.state,
                "kind": reg.kind,
                "readable": reg.readable(),
            })),
            "trace": r.trace,
        }))
    }

    /// Reads the old bytes, writes (lifting protection if needed), journals and verifies.
    fn commit_write(&self, p: &Process, addr: u64, expression: &str, value_type: Option<String>, data: &[u8]) -> CoreResult<Value> {
        let ps = p.pointer_size();
        if data.is_empty() || data.len() > MAX_WRITE_BYTES {
            return Err(MemError::InvalidArg(format!("write size must be 1..={MAX_WRITE_BYTES} bytes")));
        }
        let mut old = vec![0u8; data.len()];
        p.read(addr, &mut old).map_err(|e| match e {
            MemError::Read { reason, .. } => MemError::Write {
                addr,
                size: data.len(),
                reason: format!("original bytes are unreadable ({reason}); nothing was written"),
            },
            other => other,
        })?;
        let outcome = p.write_force(addr, data)?;
        let mut after = vec![0u8; data.len()];
        let verified = p.read(addr, &mut after).is_ok() && after == data;
        let id = self.journal.lock().unwrap().record(
            NewWrite {
                pid: p.pid(),
                process: p.name().to_string(),
                address: addr,
                expression: expression.to_string(),
                value_type,
                old_bytes: old.clone(),
                new_bytes: data.to_vec(),
                protection_changes: outcome.protection_changes.clone(),
            },
            ps,
        );
        let modules = p.modules().unwrap_or_default();
        let note = if verified {
            Value::Null
        } else {
            json!(format!(
                "read-back differs: memory now holds {} (the program may have overwritten it)",
                value::hex_bytes(&after)
            ))
        };
        Ok(json!({
            "write_id": id,
            "address": format::addr(addr, ps),
            "symbol": address::symbolize(&modules, addr),
            "size": data.len(),
            "old_bytes": value::hex_bytes(&old),
            "new_bytes": value::hex_bytes(data),
            "verified": verified,
            "note": note,
            "protection_changes": outcome.protection_changes.iter().map(|c| json!({
                "base": format::addr(c.base, ps),
                "size": format::size(c.size),
                "original": c.original,
                "restored": true,
            })).collect::<Vec<_>>(),
        }))
    }

    fn decode_elements(ty: ValueType, bytes: &[u8], ps: usize, be: bool) -> Value {
        match ty {
            ValueType::Scalar(s) => {
                let n = s.size(ps);
                let vals: Vec<Value> = bytes.chunks_exact(n).map(|c| value::decode(ty, c, ps, be)["value"].clone()).collect();
                if vals.len() == 1 { vals.into_iter().next().unwrap() } else { json!(vals) }
            }
            _ => value::decode(ty, bytes, ps, be)["value"].clone(),
        }
    }

    /// Encodes a value; `ptr` values may be address expressions.
    fn encode_value(p: &Process, ty: ValueType, v: &Value, be: bool, null_terminate: bool) -> CoreResult<Vec<u8>> {
        let resolve_ptr = |v: &Value| -> CoreResult<Value> {
            match v {
                Value::String(s) => Ok(json!(address::resolve(p.as_ref(), s, &[])?.address)),
                other => Ok(other.clone()),
            }
        };
        let val = match (&ty, v) {
            (ValueType::Scalar(Scalar::Ptr), Value::Array(items)) => {
                Value::Array(items.iter().map(resolve_ptr).collect::<CoreResult<Vec<_>>>()?)
            }
            (ValueType::Scalar(Scalar::Ptr), v) => resolve_ptr(v)?,
            (_, v) => v.clone(),
        };
        value::encode(ty, &val, p.pointer_size(), be, null_terminate)
    }

    fn type_label(ty: ValueType) -> String {
        match ty {
            ValueType::Scalar(s) => s.name().to_string(),
            ValueType::Bytes(_) => "bytes".into(),
            ValueType::Utf8(_) => "utf8".into(),
            ValueType::Utf16(_) => "utf16".into(),
        }
    }

    /// Named template, or an inline anonymous struct.
    fn struct_def(&self, name: &Option<String>, fields: &Option<Vec<FieldDef>>, packed: Option<bool>) -> CoreResult<StructDef> {
        match (name, fields) {
            (Some(n), None) => self
                .structs
                .lock()
                .unwrap()
                .get(n)
                .cloned()
                .ok_or_else(|| MemError::InvalidArg(format!("no struct named '{n}'; see list_structs"))),
            (None, Some(f)) => Ok(StructDef {
                name: "inline".into(),
                fields: f.clone(),
                packed: packed.unwrap_or(false),
                size: None,
                description: None,
            }),
            _ => Err(MemError::InvalidArg("pass either `struct` (a template name) or inline `fields`".into())),
        }
    }

    pub fn do_define_struct(&self, prm: DefineStructParams) -> CoreResult<Value> {
        let def = StructDef {
            name: prm.name,
            fields: prm.fields,
            packed: prm.packed.unwrap_or(false),
            size: prm.size,
            description: prm.description,
        };
        let mut reg = self.structs.lock().unwrap();
        let replaced = reg.define(def.clone())?;
        let l32 = structs::layout_of(&reg, &def, 4)?;
        let l64 = structs::layout_of(&reg, &def, 8)?;
        let ps = self.attached.lock().unwrap().as_ref().map(|p| p.pointer_size()).unwrap_or(8);
        let layout = if ps == 4 { &l32 } else { &l64 };
        Ok(json!({
            "defined": def.name,
            "replaced": replaced,
            "size_x86": format::size(l32.size),
            "size_x64": format::size(l64.size),
            "layout": layout.to_json(ps),
            "saved_to": reg.file().map(|f| f.display().to_string()),
        }))
    }

    pub fn do_list_structs(&self, prm: ListStructsParams) -> CoreResult<Value> {
        let reg = self.structs.lock().unwrap();
        let ps = self.attached.lock().unwrap().as_ref().map(|p| p.pointer_size()).unwrap_or(8);
        if let Some(name) = prm.name.as_deref().filter(|n| !n.is_empty()) {
            let def = reg.get(name).ok_or_else(|| MemError::InvalidArg(format!("no struct named '{name}'")))?;
            return Ok(json!({
                "definition": def,
                "layout": structs::layout_of(&reg, def, ps)?.to_json(ps),
            }));
        }
        let items: Vec<Value> = reg
            .all()
            .map(|d| {
                json!({
                    "name": d.name,
                    "fields": d.fields.len(),
                    "size": structs::layout_of(&reg, d, ps).map(|l| format::size(l.size)).unwrap_or_else(|e| e.to_string()),
                    "description": d.description,
                })
            })
            .collect();
        let mut page = format::page(&items, prm.offset, prm.limit);
        page["pointer_size"] = json!(ps);
        page["file"] = json!(reg.file().map(|f| f.display().to_string()));
        Ok(page)
    }

    pub fn do_delete_struct(&self, prm: DeleteStructParams) -> CoreResult<Value> {
        let def = self.structs.lock().unwrap().delete(&prm.name)?;
        Ok(json!({ "deleted": def.name, "definition": def }))
    }

    pub fn do_read_struct(&self, prm: ReadStructParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let def = self.struct_def(&prm.r#struct, &prm.fields, prm.packed)?;
        let depth = prm.depth.unwrap_or(1).min(structs::MAX_DEPTH);
        let count = prm.count.unwrap_or(1);
        if count == 0 || count > MAX_STRUCT_COUNT {
            return Err(MemError::InvalidArg(format!("count must be 1..={MAX_STRUCT_COUNT}")));
        }
        let reg = self.structs.lock().unwrap();
        let layout = structs::layout_of(&reg, &def, ps)?;
        if p.read_partial(addr, layout.size as usize).iter().all(|b| b.is_none()) {
            return Err(MemError::Read { addr, size: layout.size as usize, reason: p.explain_unreadable(addr) });
        }
        if count == 1 {
            let mut v = structs::read(&reg, p.as_ref(), &layout, addr, depth);
            v["symbol"] = json!(address::symbolize(&p.modules().unwrap_or_default(), addr));
            return Ok(v);
        }
        let elements: Vec<Value> =
            (0..count).map(|i| structs::read(&reg, p.as_ref(), &layout, addr + layout.size * i as u64, depth)).collect();
        Ok(json!({
            "struct": layout.name,
            "address": format::addr(addr, ps),
            "stride": format::size(layout.size),
            "count": count,
            "elements": elements,
        }))
    }

    pub fn do_write_struct(&self, prm: WriteStructParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let def = self.struct_def(&prm.r#struct, &prm.fields, prm.packed)?;
        let values = prm
            .values
            .as_object()
            .filter(|m| !m.is_empty())
            .ok_or_else(|| MemError::InvalidArg("`values` must be a non-empty object {\"field.path\": value}".into()))?;
        // Resolve and encode everything first, so a bad entry writes nothing.
        let mut plan = Vec::new();
        {
            let reg = self.structs.lock().unwrap();
            let layout = structs::layout_of(&reg, &def, ps)?;
            for (path, v) in values {
                let (off, ty, span) = structs::field_at_path(&reg, &layout, path, ps)?;
                let data = Self::encode_value(&p, ty, v, false, true)
                    .map_err(|e| MemError::InvalidArg(format!("field '{path}': {e}")))?;
                if data.len() as u64 > span {
                    return Err(MemError::InvalidArg(format!(
                        "field '{path}': {} bytes do not fit into {span} bytes",
                        data.len()
                    )));
                }
                plan.push((path.clone(), off, ty, data));
            }
        }
        let mut results = Vec::new();
        for (path, off, ty, data) in plan {
            let expr = format!("{}+0x{off:X} ({}.{path})", prm.address, def.name);
            let mut r = self.commit_write(&p, addr + off, &expr, Some(Self::type_label(ty)), &data)?;
            let old = value::parse_hex_bytes(r["old_bytes"].as_str().unwrap()).unwrap_or_default();
            r["field"] = json!(path);
            r["old_value"] = Self::decode_elements(ty, &old, ps, false);
            r["new_value"] = Self::decode_elements(ty, &data, ps, false);
            results.push(r);
        }
        Ok(json!({ "struct": def.name, "address": format::addr(addr, ps), "writes": results }))
    }

    fn aob_ranges(
        &self,
        p: &Process,
        module: &Option<String>,
        section: &Option<String>,
        protection: &Option<String>,
        start: &Option<String>,
        end: &Option<String>,
    ) -> CoreResult<(Vec<(u64, u64)>, String)> {
        let eval = |e: &Option<String>| -> CoreResult<Option<u64>> {
            e.as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(|s| address::resolve(p.as_ref(), s, &[]).map(|r| r.address))
                .transpose()
        };
        let scope = Scope {
            module: module.clone(),
            section: section.clone(),
            start: eval(start)?,
            end: eval(end)?,
            protection: protection.clone(),
            skip_mapped: false,
        };
        pattern::resolve_ranges(p.as_ref(), &scope)
    }

    pub fn do_aob_scan(&self, prm: AobScanParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let pat = Pattern::parse(&prm.pattern, prm.mask.as_deref())?;
        let (ranges, desc) = self.aob_ranges(&p, &prm.module, &prm.section, &prm.protection, &prm.start, &prm.end)?;
        let limit = prm.limit.unwrap_or(100).clamp(1, MAX_AOB_LIMIT);
        let align = prm.alignment.unwrap_or(1).max(1);
        let started = std::time::Instant::now();
        let r = pattern::scan(p.as_ref(), &pat, &ranges, align, limit);
        let elapsed = started.elapsed();
        let modules = p.modules().unwrap_or_default();
        let shown = pat.len().min(64);
        let matches: Vec<Value> = r
            .matches
            .iter()
            .map(|&a| {
                let bytes = p.read_partial(a, shown);
                json!({
                    "address": format::addr(a, ps),
                    "symbol": address::symbolize(&modules, a),
                    "bytes": bytes.iter().map(|b| b.map(|b| format!("{b:02X}")).unwrap_or_else(|| "??".into())).collect::<Vec<_>>().join(" "),
                })
            })
            .collect();
        Ok(json!({
            "pattern": pat.display(),
            "length": pat.len(),
            "scope": desc,
            "ranges": ranges.len(),
            "bytes_scanned": r.bytes_scanned,
            "elapsed_ms": elapsed.as_millis() as u64,
            "count": matches.len(),
            "truncated": r.truncated,
            "matches": matches,
        }))
    }

    pub fn do_aob_resolve(&self, prm: AobResolveParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let pat = Pattern::parse(&prm.pattern, prm.mask.as_deref())?;
        let (ranges, desc) = self.aob_ranges(&p, &prm.module, &prm.section, &prm.protection, &None, &None)?;
        let want = prm.index.unwrap_or(0);
        let r = pattern::scan(p.as_ref(), &pat, &ranges, 1, (want + 1).max(8));
        let fmt = |a: u64| format::addr(a, ps);
        let m = match (prm.index, r.matches.as_slice()) {
            (_, []) => return Err(MemError::InvalidArg(format!("signature {} not found in {desc}", pat.display()))),
            (None, [one]) => *one,
            (None, many) => {
                return Err(MemError::InvalidArg(format!(
                    "signature {} matches {}{} times in {desc} ({}); pass `index`, lengthen the pattern or narrow the scope",
                    pat.display(),
                    many.len(),
                    if r.truncated { "+" } else { "" },
                    many.iter().take(4).map(|a| fmt(*a)).collect::<Vec<_>>().join(", ")
                )));
            }
            (Some(i), all) => *all.get(i).ok_or_else(|| {
                MemError::InvalidArg(format!("index {i} out of range: only {} matches in {desc}", all.len()))
            })?,
        };
        let mut trace = vec![json!({"op": format!("sig({}) in {desc}", pat.display()), "value": fmt(m)})];
        let off = prm.offset.unwrap_or(0);
        let base = m.wrapping_add(off as u64);
        if off != 0 {
            trace.push(json!({"op": format!("{off:+#x}"), "value": fmt(base)}));
        }
        let mode = prm.mode.as_deref().unwrap_or("address").to_ascii_lowercase();
        let read4 = |at: u64| -> CoreResult<[u8; 4]> {
            let mut b = [0u8; 4];
            p.read(at, &mut b)?;
            Ok(b)
        };
        let (address, step) = match mode.as_str() {
            "address" => (base, None),
            "rip" => {
                let d = prm.disp_offset.unwrap_or(3);
                let len = prm.insn_len.unwrap_or(7);
                let disp = i32::from_le_bytes(read4(base + d)?);
                let mut t = base.wrapping_add(len).wrapping_add(disp as i64 as u64);
                if ps == 4 {
                    t &= 0xFFFF_FFFF;
                }
                (t, Some(format!("rip({}, {d:#x}, {len:#x}) disp {disp:+#x}", fmt(base))))
            }
            "abs32" => {
                let d = prm.disp_offset.unwrap_or(0);
                (u32::from_le_bytes(read4(base + d)?) as u64, Some(format!("abs32({}, {d:#x})", fmt(base))))
            }
            "ptr" => (p.read_u64_ptr(base)?, Some(format!("[{}]", fmt(base)))),
            other => return Err(MemError::InvalidArg(format!("unknown mode '{other}' (address|rip|abs32|ptr)"))),
        };
        if let Some(op) = step {
            trace.push(json!({"op": op, "value": fmt(address)}));
        }
        // An equivalent expression for read_value / write_value (only for a unique match).
        let expression = prm.index.is_none().then(|| {
            let mut sig = format!("sig(\"{}\"", pat.display());
            if let Some(m) = prm.module.as_deref().filter(|m| !m.is_empty()) {
                sig.push_str(&format!(", \"{m}\""));
                if let Some(sec) = prm.section.as_deref().filter(|s| !s.is_empty()) {
                    sig.push_str(&format!(", \"{sec}\""));
                }
            }
            sig.push(')');
            let at = match off {
                0 => sig,
                o if o > 0 => format!("{sig}+0x{o:X}"),
                o => format!("{sig}-0x{:X}", o.unsigned_abs()),
            };
            match mode.as_str() {
                "rip" => format!("rip({at}, 0x{:X}, 0x{:X})", prm.disp_offset.unwrap_or(3), prm.insn_len.unwrap_or(7)),
                "abs32" => format!("abs32({at}, 0x{:X})", prm.disp_offset.unwrap_or(0)),
                "ptr" => format!("[{at}]"),
                _ => at,
            }
        });
        let modules = p.modules().unwrap_or_default();
        Ok(json!({
            "match": fmt(m),
            "address": fmt(address),
            "symbol": address::symbolize(&modules, address),
            "mode": mode,
            "expression": expression,
            "trace": trace,
        }))
    }

    fn scan_session(&self, id: u64) -> CoreResult<Arc<Mutex<ScanSession>>> {
        self.scans
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| MemError::InvalidArg(format!("no scan with id {id}; see scan_list")))
    }

    fn scan_summary(&self, p: &Process, sess: &ScanSession, extra: Value) -> CoreResult<Value> {
        let ps = p.pointer_size();
        let modules = p.modules().unwrap_or_default();
        let preview: Vec<Value> = scan::page(&sess.generation, &sess.spec, 0, PREVIEW)?
            .into_iter()
            .map(|(a, v)| {
                json!({
                    "address": format::addr(a, ps),
                    "symbol": address::symbolize(&modules, a),
                    "value": sess.spec.ty.decode(&v).to_json(),
                })
            })
            .collect();
        let total = sess.generation.total;
        let mut out = json!({
            "scan_id": sess.id,
            "type": sess.spec.ty.name(),
            "alignment": sess.spec.align,
            "scope": sess.scope,
            "scans": sess.history.len(),
            "total": total,
            "storage": {
                "memory_bytes": sess.generation.memory_bytes(),
                "disk_bytes": sess.generation.disk_bytes(),
            },
            "preview": preview,
            "hint": if total == 0 {
                "no candidates left; start a new scan (maybe with another type, alignment 1 or float_mode)"
            } else if total as usize > PREVIEW {
                "change the value in the program, then narrow with scan_next; page with scan_results"
            } else {
                "few candidates: verify with read_value / write_value"
            },
        });
        if sess.spec.ty.is_float() {
            out["float_mode"] = json!(sess.spec.float_mode.name());
        }
        if let (Value::Object(o), Value::Object(e)) = (&mut out, extra) {
            o.extend(e);
        }
        Ok(out)
    }

    pub fn do_scan_start(&self, prm: ScanStartParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ty = ScanType::parse(&prm.value_type, p.pointer_size())?;
        let cond_name = prm.condition.clone().unwrap_or_else(|| if prm.value.is_some() { "exact".into() } else { String::new() });
        if cond_name.is_empty() {
            return Err(MemError::InvalidArg(format!(
                "pass `value` (exact scan) or a `condition` ({})",
                scan::cond::FIRST_CONDITIONS
            )));
        }
        let cond = Cond::parse(&cond_name, prm.value.as_ref(), prm.value2.as_ref(), ty, true)?;
        let align = prm.alignment.unwrap_or_else(|| ty.default_alignment()).max(1);
        let float_mode = FloatMode::parse(prm.float_mode.as_deref(), prm.tolerance)?;
        let spec = ScanSpec { ty, align, float_mode };
        let budget = prm.max_memory_mb.unwrap_or(DEFAULT_SCAN_MEMORY_MB).saturating_mul(1 << 20);
        if self.scans.lock().unwrap().len() >= MAX_SCAN_SESSIONS {
            return Err(MemError::InvalidArg(format!("too many open scans ({MAX_SCAN_SESSIONS}); close some with scan_close")));
        }
        let eval = |e: &Option<String>| -> CoreResult<Option<u64>> {
            e.as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(|s| address::resolve(p.as_ref(), s, &[]).map(|r| r.address))
                .transpose()
        };
        let scope = Scope {
            module: prm.module.clone(),
            section: prm.section.clone(),
            start: eval(&prm.start)?,
            end: eval(&prm.end)?,
            protection: Some(prm.protection.clone().unwrap_or_else(|| "w".into())),
            skip_mapped: !prm.include_mapped.unwrap_or(false),
        };
        let (ranges, desc) = pattern::resolve_ranges(p.as_ref(), &scope)?;
        let started = std::time::Instant::now();
        let (generation, scanned) = scan::first_scan(p.as_ref(), &spec, &cond, &ranges, budget)?;
        let elapsed = started.elapsed().as_millis() as u64;
        let id = self.next_scan_id.fetch_add(1, Ordering::Relaxed);
        let sess = ScanSession {
            id,
            pid: p.pid(),
            spec,
            scope: desc,
            budget,
            history: vec![json!({"condition": cond.describe(), "total": generation.total})],
            generation,
        };
        let out = self.scan_summary(&p, &sess, json!({"condition": cond.describe(), "bytes_scanned": scanned, "elapsed_ms": elapsed}))?;
        self.scans.lock().unwrap().insert(id, Arc::new(Mutex::new(sess)));
        Ok(out)
    }

    pub fn do_scan_next(&self, prm: ScanNextParams) -> CoreResult<Value> {
        let p = self.process()?;
        let sess = self.scan_session(prm.scan_id)?;
        let mut sess = sess.lock().unwrap();
        scan::check_pid(sess.pid, p.pid(), sess.id)?;
        let cond = Cond::parse(&prm.condition, prm.value.as_ref(), prm.value2.as_ref(), sess.spec.ty, false)?;
        let started = std::time::Instant::now();
        let previous = sess.generation.total;
        let next = scan::next_scan(p.as_ref(), &sess.spec, &cond, &sess.generation, sess.budget)?;
        let elapsed = started.elapsed().as_millis() as u64;
        sess.generation = next;
        let total = sess.generation.total;
        sess.history.push(json!({"condition": cond.describe(), "total": total}));
        self.scan_summary(&p, &sess, json!({"condition": cond.describe(), "previous_total": previous, "elapsed_ms": elapsed}))
    }

    pub fn do_scan_results(&self, prm: ScanResultsParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let sess = self.scan_session(prm.scan_id)?;
        let sess = sess.lock().unwrap();
        scan::check_pid(sess.pid, p.pid(), sess.id)?;
        let offset = prm.offset.unwrap_or(0);
        let limit = prm.limit.unwrap_or(50).clamp(1, 1000);
        let modules = p.modules().unwrap_or_default();
        let size = sess.spec.ty.size;
        let items: Vec<Value> = scan::page(&sess.generation, &sess.spec, offset, limit)?
            .into_iter()
            .map(|(a, prev)| {
                let mut cur = vec![0u8; size];
                let now = p.read(a, &mut cur).ok().map(|_| sess.spec.ty.decode(&cur).to_json());
                json!({
                    "address": format::addr(a, ps),
                    "symbol": address::symbolize(&modules, a),
                    "value": now,
                    "previous": sess.spec.ty.decode(&prev).to_json(),
                })
            })
            .collect();
        let total = sess.generation.total;
        Ok(json!({
            "scan_id": sess.id,
            "type": sess.spec.ty.name(),
            "total": total,
            "offset": offset,
            "returned": items.len(),
            "has_more": offset + (items.len() as u64) < total,
            "items": items,
        }))
    }

    pub fn do_scan_close(&self, prm: ScanCloseParams) -> CoreResult<Value> {
        let removed = self.scans.lock().unwrap().remove(&prm.scan_id);
        match removed {
            Some(_) => Ok(json!({ "closed": prm.scan_id })),
            None => Err(MemError::InvalidArg(format!("no scan with id {}", prm.scan_id))),
        }
    }

    pub fn do_scan_list(&self) -> CoreResult<Value> {
        let scans: Vec<Arc<Mutex<ScanSession>>> = self.scans.lock().unwrap().values().cloned().collect();
        let mut items: Vec<Value> = scans
            .iter()
            .map(|s| {
                let s = s.lock().unwrap();
                json!({
                    "scan_id": s.id,
                    "pid": s.pid,
                    "type": s.spec.ty.name(),
                    "scope": s.scope,
                    "total": s.generation.total,
                    "history": s.history,
                    "memory_bytes": s.generation.memory_bytes(),
                    "disk_bytes": s.generation.disk_bytes(),
                })
            })
            .collect();
        items.sort_by_key(|v| v["scan_id"].as_u64());
        Ok(json!({ "scans": items }))
    }

    /// Stops all freezes and watches (on detach / attach). Returns (freezes, watches) stopped.
    fn stop_all_background(&self, reason: &str) -> (usize, usize) {
        let freezes: Vec<Freeze> = self.freezes.lock().unwrap().drain().map(|(_, f)| f).collect();
        let watches: Vec<Watch> = self.watches.lock().unwrap().drain().map(|(_, w)| w).collect();
        let counts = (freezes.len(), watches.len());
        for f in freezes {
            f.stop(false, reason);
        }
        for w in watches {
            w.stop(reason);
        }
        counts
    }

    fn background_target(&self, p: &Process, expr: &str, offsets: &Option<Vec<Offset>>, re_resolve: Option<bool>) -> CoreResult<Target> {
        let offs = offsets.clone().unwrap_or_default();
        let addr = address::resolve(p.as_ref(), expr, &offs)?.address;
        let dynamic = expr.contains('[') || !offs.is_empty();
        Ok(Target { expression: expr.to_string(), offsets: offs, re_resolve: re_resolve.unwrap_or(dynamic), address: addr })
    }

    fn check_background_capacity(&self) -> CoreResult<()> {
        let n = self.freezes.lock().unwrap().len() + self.watches.lock().unwrap().len();
        if n >= MAX_BACKGROUND {
            return Err(MemError::InvalidArg(format!("too many freezes/watches ({MAX_BACKGROUND}); stop some first")));
        }
        Ok(())
    }

    pub fn do_freeze(&self, prm: FreezeParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        self.check_background_capacity()?;
        let target = self.background_target(&p, &prm.address, &prm.offsets, prm.re_resolve)?;
        let (ty, bytes) = match &prm.value {
            Some(v) => {
                let ty = ValueType::parse(&prm.value_type, prm.length.or(Some(1)))?;
                let data = Self::encode_value(&p, ty, v, false, true)?;
                let ty = match ty {
                    ValueType::Bytes(_) => ValueType::Bytes(data.len()),
                    ValueType::Utf8(_) => ValueType::Utf8(data.len()),
                    ValueType::Utf16(_) => ValueType::Utf16(data.len() / 2),
                    ValueType::Scalar(s) if data.len() > s.size(ps) => {
                        return Err(MemError::InvalidArg("freeze holds a single value; arrays are not supported".into()));
                    }
                    other => other,
                };
                (ty, data)
            }
            None => {
                let ty = ValueType::parse(&prm.value_type, prm.length)?;
                let mut b = vec![0u8; ty.size(ps)];
                p.read(target.address, &mut b)?;
                (ty, b)
            }
        };
        if bytes.len() > MAX_WRITE_BYTES {
            return Err(MemError::InvalidArg(format!("freeze size must be <= {MAX_WRITE_BYTES} bytes")));
        }
        let mut original = vec![0u8; bytes.len()];
        p.read(target.address, &mut original)?;
        let mode = FreezeMode::parse(prm.mode.as_deref(), matches!(ty, ValueType::Scalar(_)))?;
        let interval = background::check_interval(prm.interval_ms.unwrap_or(100))?;
        let id = self.next_bg_id.fetch_add(1, Ordering::Relaxed);
        let f = Freeze::start(id, p.clone(), target, ty, bytes, original, mode, interval);
        let mut out = f.to_json();
        out["symbol"] = json!(address::symbolize(&p.modules().unwrap_or_default(), f.target.address));
        self.freezes.lock().unwrap().insert(id, f);
        Ok(out)
    }

    pub fn do_unfreeze(&self, prm: UnfreezeParams) -> CoreResult<Value> {
        let restore = prm.restore.unwrap_or(false);
        let taken: Vec<Freeze> = {
            let mut map = self.freezes.lock().unwrap();
            match (prm.freeze_id, prm.all.unwrap_or(false)) {
                (Some(id), _) => vec![map.remove(&id).ok_or_else(|| MemError::InvalidArg(format!("no freeze with id {id}")))?],
                (None, true) => map.drain().map(|(_, f)| f).collect(),
                (None, false) => return Err(MemError::InvalidArg("pass `freeze_id` or `all: true`".into())),
            }
        };
        let stopped: Vec<Value> = taken.into_iter().map(|f| f.stop(restore, "unfrozen")).collect();
        Ok(json!({ "stopped": stopped }))
    }

    pub fn do_list_freezes(&self) -> CoreResult<Value> {
        let map = self.freezes.lock().unwrap();
        let mut items: Vec<Value> = map.values().map(|f| f.to_json()).collect();
        items.sort_by_key(|v| v["freeze_id"].as_u64());
        Ok(json!({ "freezes": items }))
    }

    pub fn do_watch(&self, prm: WatchParams) -> CoreResult<Value> {
        let p = self.process()?;
        self.check_background_capacity()?;
        let target = self.background_target(&p, &prm.address, &prm.offsets, prm.re_resolve)?;
        let ty = ValueType::parse(&prm.value_type, prm.length)?;
        let mut probe = vec![0u8; ty.size(p.pointer_size())];
        p.read(target.address, &mut probe)?;
        let interval = background::check_interval(prm.interval_ms.unwrap_or(100))?;
        let max_events = prm.max_events.unwrap_or(1000).clamp(1, background::MAX_EVENTS);
        let id = self.next_bg_id.fetch_add(1, Ordering::Relaxed);
        let w = Watch::start(id, p.clone(), target, ty, interval, max_events, probe.clone());
        let mut out = w.summary();
        out["symbol"] = json!(address::symbolize(&p.modules().unwrap_or_default(), w.target.address));
        out["initial"] = value::decode(ty, &probe, p.pointer_size(), false)["value"].clone();
        self.watches.lock().unwrap().insert(id, w);
        Ok(out)
    }

    pub fn do_watch_read(&self, prm: WatchReadParams) -> CoreResult<Value> {
        let map = self.watches.lock().unwrap();
        let w = map.get(&prm.watch_id).ok_or_else(|| MemError::InvalidArg(format!("no watch with id {}", prm.watch_id)))?;
        Ok(w.read(prm.since.unwrap_or(0), prm.limit.unwrap_or(200).clamp(1, 5000)))
    }

    pub fn do_unwatch(&self, prm: UnwatchParams) -> CoreResult<Value> {
        let taken: Vec<Watch> = {
            let mut map = self.watches.lock().unwrap();
            match (prm.watch_id, prm.all.unwrap_or(false)) {
                (Some(id), _) => vec![map.remove(&id).ok_or_else(|| MemError::InvalidArg(format!("no watch with id {id}")))?],
                (None, true) => map.drain().map(|(_, w)| w).collect(),
                (None, false) => return Err(MemError::InvalidArg("pass `watch_id` or `all: true`".into())),
            }
        };
        let stopped: Vec<Value> = taken.into_iter().map(|w| w.stop("unwatched")).collect();
        Ok(json!({ "stopped": stopped }))
    }

    pub fn do_list_watches(&self) -> CoreResult<Value> {
        let map = self.watches.lock().unwrap();
        let mut items: Vec<Value> = map.values().map(|w| w.summary()).collect();
        items.sort_by_key(|v| v["watch_id"].as_u64());
        Ok(json!({ "watches": items }))
    }

    pub fn do_pointer_scan(&self, prm: PointerScanParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        if self.ptr_scans.lock().unwrap().len() >= MAX_PTR_SCANS {
            return Err(MemError::InvalidArg(format!("too many pointer scans ({MAX_PTR_SCANS}); close some")));
        }
        let target = address::resolve(p.as_ref(), &prm.target, prm.offsets.as_deref().unwrap_or(&[]))?.address;
        let max_offset = match &prm.max_offset {
            None => 0x1000,
            Some(crate::structs::FieldOffset::Num(n)) => *n,
            Some(crate::structs::FieldOffset::Str(s)) => address::parse_number(s)?,
        };
        let opts = PtrScanOptions {
            max_depth: prm.max_depth.unwrap_or(4).clamp(1, pointer::MAX_DEPTH),
            max_offset,
            max_results: prm.max_results.unwrap_or(1000).clamp(1, 100_000),
            max_nodes: prm.max_nodes.unwrap_or(1_000_000).clamp(1, 20_000_000),
            include_mapped: prm.include_mapped.unwrap_or(false),
            align: prm.alignment.unwrap_or(ps as u64).max(1),
        };
        let modules = p.modules()?;
        if let Some(list) = &prm.modules {
            for n in list {
                if address::lookup_module(&modules, n)?.is_none() {
                    return Err(MemError::InvalidArg(format!("module '{n}' is not loaded")));
                }
            }
        }
        let allowed: Option<Vec<String>> = prm.modules.as_ref().map(|list| {
            list.iter()
                .filter_map(|n| address::lookup_module(&modules, n).ok().flatten().map(|m| m.name.clone()))
                .collect()
        });
        let mut stats = PtrScanStats::default();
        let t0 = std::time::Instant::now();
        let index = pointer::build_index(p.as_ref(), &opts, &mut stats)?;
        stats.index_ms = t0.elapsed().as_millis() as u64;
        let t1 = std::time::Instant::now();
        let chains = pointer::search(&index, &modules, allowed.as_deref(), target, &opts, &mut stats);
        stats.search_ms = t1.elapsed().as_millis() as u64;
        drop(index);
        let id = self.next_ptr_id.fetch_add(1, Ordering::Relaxed);
        let preview: Vec<Value> = chains.iter().take(PREVIEW).map(Chain::to_json).collect();
        let out = json!({
            "ptr_scan_id": id,
            "target": pointer::describe_target(p.as_ref(), &modules, target),
            "options": {
                "max_depth": opts.max_depth,
                "max_offset": format::size(opts.max_offset),
                "alignment": opts.align,
                "modules": allowed,
            },
            "total": chains.len(),
            "stats": stats,
            "preview": preview,
            "hint": if chains.is_empty() {
                "no chains: increase max_depth / max_offset, or check that the target is a heap object reachable from a module"
            } else {
                "restart the program, find the value again and call pointer_rescan with the new target to keep stable chains"
            },
        });
        let sess = PtrSession {
            id,
            pid: p.pid(),
            process_name: p.name().to_string(),
            target,
            history: vec![json!({"event": "scan", "target": format::addr(target, ps), "chains": chains.len()})],
            chains,
            stats,
        };
        self.ptr_scans.lock().unwrap().insert(id, sess);
        Ok(out)
    }

    pub fn do_pointer_results(&self, prm: PointerResultsParams) -> CoreResult<Value> {
        let map = self.ptr_scans.lock().unwrap();
        let sess = map.get(&prm.ptr_scan_id).ok_or_else(|| MemError::InvalidArg(format!("no pointer scan with id {}", prm.ptr_scan_id)))?;
        let offset = prm.offset.unwrap_or(0).min(sess.chains.len());
        let limit = prm.limit.unwrap_or(50).clamp(1, 1000);
        let p = if prm.verify.unwrap_or(true) { self.process().ok() } else { None };
        let same_process = p.as_ref().is_some_and(|p| p.pid() == sess.pid);
        let items: Vec<Value> = sess.chains[offset..(offset + limit).min(sess.chains.len())]
            .iter()
            .map(|c| {
                let mut v = c.to_json();
                if let Some(p) = &p {
                    match c.resolve(p.as_ref()) {
                        Ok(a) => {
                            v["resolves_to"] = json!(format::addr(a, p.pointer_size()));
                            if same_process {
                                v["valid"] = json!(a == sess.target);
                            }
                        }
                        Err(e) => {
                            v["resolves_to"] = Value::Null;
                            v["error"] = json!(e.to_string());
                            v["valid"] = json!(false);
                        }
                    }
                }
                v
            })
            .collect();
        Ok(json!({
            "ptr_scan_id": sess.id,
            "process": sess.process_name,
            "pid": sess.pid,
            "target": format!("0x{:X}", sess.target),
            "total": sess.chains.len(),
            "offset": offset,
            "returned": items.len(),
            "has_more": offset + items.len() < sess.chains.len(),
            "items": items,
        }))
    }

    pub fn do_pointer_rescan(&self, prm: PointerRescanParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let (chains, old_target, old_pid) = {
            let map = self.ptr_scans.lock().unwrap();
            let s = map.get(&prm.ptr_scan_id).ok_or_else(|| MemError::InvalidArg(format!("no pointer scan with id {}", prm.ptr_scan_id)))?;
            (s.chains.clone(), s.target, s.pid)
        };
        let target = match &prm.target {
            Some(t) => address::resolve(p.as_ref(), t, prm.offsets.as_deref().unwrap_or(&[]))?.address,
            None if old_pid == p.pid() => old_target,
            None => {
                return Err(MemError::InvalidArg(format!(
                    "the scan was made in pid {old_pid}; pass the new `target` address in pid {} (find the value again first)",
                    p.pid()
                )));
            }
        };
        let before = chains.len();
        let kept = pointer::rescan(p.as_ref(), &chains, target);
        let after = kept.len();
        let preview: Vec<Value> = kept.iter().take(PREVIEW).map(Chain::to_json).collect();
        let mut map = self.ptr_scans.lock().unwrap();
        let s = map.get_mut(&prm.ptr_scan_id).ok_or_else(|| MemError::InvalidArg("pointer scan was closed".into()))?;
        s.chains = kept;
        s.target = target;
        s.pid = p.pid();
        s.process_name = p.name().to_string();
        s.history.push(json!({"event": "rescan", "target": format::addr(target, ps), "pid": p.pid(), "chains": after}));
        Ok(json!({
            "ptr_scan_id": s.id,
            "target": pointer::describe_target(p.as_ref(), &p.modules().unwrap_or_default(), target),
            "before": before,
            "after": after,
            "removed": before - after,
            "history": s.history,
            "preview": preview,
        }))
    }

    pub fn do_pointer_close(&self, prm: PointerCloseParams) -> CoreResult<Value> {
        match self.ptr_scans.lock().unwrap().remove(&prm.ptr_scan_id) {
            Some(_) => Ok(json!({ "closed": prm.ptr_scan_id })),
            None => Err(MemError::InvalidArg(format!("no pointer scan with id {}", prm.ptr_scan_id))),
        }
    }

    pub fn do_pointer_list(&self) -> CoreResult<Value> {
        let map = self.ptr_scans.lock().unwrap();
        let mut items: Vec<Value> = map
            .values()
            .map(|s| {
                json!({
                    "ptr_scan_id": s.id,
                    "process": s.process_name,
                    "pid": s.pid,
                    "target": format!("0x{:X}", s.target),
                    "chains": s.chains.len(),
                    "pointers_indexed": s.stats.pointers,
                    "history": s.history,
                })
            })
            .collect();
        items.sort_by_key(|v| v["ptr_scan_id"].as_u64());
        Ok(json!({ "pointer_scans": items }))
    }

    pub fn do_disassemble(&self, prm: DisassembleParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let start = self.resolve(&p, &prm.address, &prm.offsets)?;
        let syntax = Syntax::parse(prm.syntax.as_deref())?;
        let count = prm.count.unwrap_or(30).clamp(1, disasm::MAX_COUNT);
        let max_bytes = prm.size.unwrap_or(count * disasm::MAX_INSN_LEN).clamp(1, disasm::MAX_BYTES);
        let opts = DecodeOptions { count, max_bytes, until_ret: prm.until_ret.unwrap_or(false) };
        let lines = disasm::decode(p.as_ref(), start, &opts);
        if lines.first().is_some_and(|l| l.kind == LineKind::Unreadable) {
            return Err(MemError::Read { addr: start, size: 1, reason: p.explain_unreadable(start) });
        }
        let table = self.symbols.lock().unwrap().table_for(p.as_ref(), &disasm::referenced_addresses(p.as_ref(), &lines));
        let rendered = disasm::render(p.as_ref(), &lines, &table, syntax, &HashMap::new());
        let last = lines.last().unwrap();
        let next = last.address + last.bytes.len() as u64;
        let stopped = match last.kind {
            LineKind::Unreadable => "unreadable memory",
            _ if opts.until_ret && rendered.last().is_some_and(|r| r.flow == "ret") => "ret",
            _ if lines.len() >= count => "count",
            _ => "size",
        };
        let mut out = json!({
            "address": format::addr(start, ps),
            "symbol": table.name(start),
            "syntax": format!("{syntax:?}").to_ascii_lowercase(),
            "instructions": lines.iter().filter(|l| l.kind != LineKind::Unreadable).count(),
            "bytes": next - start,
            "next": format::addr(next, ps),
            "stopped_by": stopped,
            "listing": disasm::listing(&rendered, prm.show_bytes.unwrap_or(true)),
        });
        if prm.details.unwrap_or(false) {
            out["details"] = json!(rendered);
        }
        Ok(out)
    }

    /// Code facts of the module containing `addr` (None outside modules).
    fn module_code(&self, p: &Process, addr: u64) -> CoreResult<Option<Arc<ModuleCode>>> {
        let modules = p.modules()?;
        match modules.iter().find(|m| m.contains(addr)) {
            Some(m) => Ok(Some(self.code.get(p.as_ref(), m)?)),
            None => Ok(None),
        }
    }

    fn locate_function(&self, p: &Process, addr: u64) -> CoreResult<(funcs::Function, Option<Arc<ModuleCode>>)> {
        let code = self.module_code(p, addr)?;
        let f = funcs::find(p.as_ref(), code.as_deref(), addr)?;
        if !f.contains_query {
            return Err(MemError::InvalidArg(format!(
                "{} is not inside a recognizable function (nearest candidate starts at {} and ends at {}); \
                 it may be padding, data or unreachable code",
                format::addr(addr, p.pointer_size()),
                format::addr(f.start, p.pointer_size()),
                format::addr(f.end, p.pointer_size())
            )));
        }
        Ok((f, code))
    }

    pub fn do_function_info(&self, prm: FunctionParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let (f, code) = self.locate_function(&p, addr)?;
        let (direct, indirect) = funcs::calls(&f);
        let mut wanted: Vec<u64> = vec![f.start, addr];
        wanted.extend(direct.iter().map(|c| c.1));
        let indirect_ptrs: Vec<(u64, Option<u64>, Option<u64>)> = indirect
            .iter()
            .map(|&(at, mem)| (at, mem, mem.and_then(|m| p.read_u64_ptr(m).ok())))
            .collect();
        wanted.extend(indirect_ptrs.iter().filter_map(|x| x.2));
        let table = self.symbols.lock().unwrap().table_for(p.as_ref(), &wanted);
        let a = |x: u64| format::addr(x, ps);
        Ok(json!({
            "query": a(addr),
            "start": a(f.start),
            "end": a(f.end),
            "size": f.end - f.start,
            "symbol": table.name(f.start),
            "module": code.as_ref().map(|c| c.module.name.clone()),
            "source": f.source,
            "fragments": f.fragments.iter().map(|&(s, e)| json!({"start": a(s), "end": a(e), "size": e - s})).collect::<Vec<_>>(),
            "instructions": f.lines.len(),
            "basic_blocks": f.blocks,
            "truncated": f.truncated,
            "calls": direct.iter().map(|&(at, t)| json!({"at": a(at), "target": a(t), "symbol": table.name(t)})).collect::<Vec<_>>(),
            "indirect_calls": indirect_ptrs.iter().map(|&(at, mem, ptr)| json!({
                "at": a(at),
                "via": mem.map(|m| table.name(m).unwrap_or_else(|| a(m))),
                "currently": ptr.map(|x| table.name(x).unwrap_or_else(|| a(x))),
            })).collect::<Vec<_>>(),
        }))
    }

    pub fn do_disassemble_function(&self, prm: DisassembleFunctionParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let syntax = Syntax::parse(prm.syntax.as_deref())?;
        let (f, code) = self.locate_function(&p, addr)?;
        let labels = funcs::local_labels(&f, code.as_ref().map(|c| &c.module));
        let table = self.symbols.lock().unwrap().table_for(p.as_ref(), &disasm::referenced_addresses(p.as_ref(), &f.lines));
        let rendered = disasm::render(p.as_ref(), &f.lines, &table, syntax, &labels);
        let show_bytes = prm.show_bytes.unwrap_or(true);
        // Separate non-contiguous parts (fragments, skipped data) with a marker line.
        let mut listing = Vec::new();
        let mut group_start = 0;
        for k in 1..=f.lines.len() {
            let gap = k == f.lines.len() || f.lines[k].address != f.lines[k - 1].address + f.lines[k - 1].bytes.len() as u64;
            if gap {
                if group_start > 0 {
                    listing.push(format!("; ... {}", table.name(f.lines[group_start].address).unwrap_or_default()));
                }
                listing.extend(disasm::listing(&rendered[group_start..k], show_bytes));
                group_start = k;
            }
        }
        let mut out = json!({
            "start": format::addr(f.start, ps),
            "end": format::addr(f.end, ps),
            "symbol": table.name(f.start),
            "source": f.source,
            "instructions": f.lines.len(),
            "syntax": format!("{syntax:?}").to_ascii_lowercase(),
            "listing": listing,
        });
        if prm.details.unwrap_or(false) {
            out["details"] = json!(rendered);
        }
        Ok(out)
    }

    pub fn do_list_functions(&self, prm: ListFunctionsParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let modules = p.modules()?;
        let m = address::lookup_module(&modules, &prm.module)?
            .ok_or_else(|| MemError::InvalidArg(format!("module '{}' is not loaded", prm.module)))?
            .clone();
        let code = self.code.get(p.as_ref(), &m)?;
        let starts: Vec<u64> = code.starts.iter().map(|s| s.0).collect();
        let table = self.symbols.lock().unwrap().table_for(p.as_ref(), &[m.base]);
        let filter = prm.filter.as_deref().map(str::to_ascii_lowercase).filter(|f| !f.is_empty());
        let items: Vec<Value> = code
            .starts
            .iter()
            .filter_map(|&(a, kind)| {
                let name = table.name(a).unwrap_or_default();
                if filter.as_ref().is_some_and(|f| !name.to_ascii_lowercase().contains(f)) {
                    return None;
                }
                let size = code.pdata.iter().find(|e| e.begin == a).map(|e| e.end - e.begin);
                Some(json!({ "address": format::addr(a, ps), "symbol": name, "source": kind, "size": size }))
            })
            .collect();
        let mut out = format::page(&items, prm.offset, prm.limit);
        out["module"] = json!(m.name);
        out["functions_total"] = json!(starts.len());
        out["from_pdata"] = json!(code.starts.iter().filter(|s| s.1 == funcs::StartKind::Pdata).count());
        out["call_targets"] = json!(code.call_targets);
        out["note"] = json!(if code.pdata.is_empty() {
            "no .pdata: functions are call targets and exports found by a linear sweep of the code sections"
        } else {
            "x64 .pdata functions plus call targets (leaf functions have no .pdata entry) and exports"
        });
        Ok(out)
    }

    pub fn do_find_xrefs(&self, prm: FindXrefsParams) -> CoreResult<Value> {
        const MAX_CANDIDATES: usize = 50_000;
        let p = self.process()?;
        let ps = p.pointer_size();
        let target = self.resolve(&p, &prm.target, &prm.offsets)?;
        let size = prm.size.unwrap_or(1).clamp(1, 1 << 20);
        let filter = prm.kind.as_deref().unwrap_or("any").to_ascii_lowercase();
        if !["any", "call", "jump", "code", "read", "write", "access", "address"].contains(&filter.as_str()) {
            return Err(MemError::InvalidArg(format!("unknown kind '{filter}' ({KIND_FILTERS})")));
        }
        let syntax = Syntax::parse(prm.syntax.as_deref())?;
        let modules = p.modules()?;

        // modules to search
        let mut search: Vec<crate::platform::Module> = Vec::new();
        match &prm.modules {
            Some(list) if list.iter().any(|n| n == "*") => search = modules.clone(),
            Some(list) => {
                for n in list {
                    let m = address::lookup_module(&modules, n)?
                        .ok_or_else(|| MemError::InvalidArg(format!("module '{n}' is not loaded")))?;
                    search.push(m.clone());
                }
            }
            None => {
                search.extend(modules.iter().find(|m| m.contains(target)).cloned());
                if let Some(main) = modules.iter().find(|m| m.name.eq_ignore_ascii_case(p.name())) {
                    search.push(main.clone());
                }
            }
        }
        search.sort_by_key(|m| m.base);
        search.dedup_by_key(|m| m.base);
        if search.is_empty() {
            return Err(MemError::InvalidArg("no module to search; pass `modules`".into()));
        }

        // (from, kind, via) candidates
        let mut cands: Vec<(u64, XrefKind, Option<u64>)> = Vec::new();
        let mut searched = Vec::new();
        let mut codes = Vec::new();
        for m in &search {
            let t0 = std::time::Instant::now();
            let code = self.code.get(p.as_ref(), m)?;
            let idx = code.xref_index(p.as_ref(), &modules);
            for x in idx.query(target, target + size) {
                cands.push((idx.base + x.from_off as u64, x.kind, None));
            }
            // pointer slots inside this module holding the target
            if prm.via_pointers.unwrap_or(true) {
                let bytes = if ps == 4 { (target as u32).to_le_bytes().to_vec() } else { target.to_le_bytes().to_vec() };
                let hex = crate::value::hex_bytes(&bytes);
                let pat = Pattern::parse(&hex, None)?;
                let scope = Scope { module: Some(m.name.clone()), ..Default::default() };
                if let Ok((ranges, _)) = pattern::resolve_ranges(p.as_ref(), &scope) {
                    for slot in pattern::scan(p.as_ref(), &pat, &ranges, ps as u64, 256).matches {
                        for x in idx.query(slot, slot + 1) {
                            cands.push((idx.base + x.from_off as u64, x.kind, Some(slot)));
                        }
                    }
                }
            }
            searched.push(json!({
                "module": m.name,
                "instructions_indexed": idx.instructions,
                "references_indexed": idx.refs.len(),
                "ms": t0.elapsed().as_millis() as u64,
            }));
            codes.push(code);
            if cands.len() > MAX_CANDIDATES {
                break;
            }
        }
        cands.sort_unstable();
        cands.dedup();
        cands.truncate(MAX_CANDIDATES);

        // decode each referencing instruction (needed for pointer-slot calls and the text)
        let lines: Vec<disasm::Line> = cands
            .iter()
            .map(|&(from, _, _)| {
                disasm::decode(p.as_ref(), from, &DecodeOptions { count: 1, max_bytes: disasm::MAX_INSN_LEN, until_ret: false })
                    .into_iter()
                    .next()
                    .unwrap()
            })
            .collect();
        let mut rows: Vec<(usize, XrefKind)> = Vec::new();
        for (k, &(_, kind, via)) in cands.iter().enumerate() {
            let eff = match (via, lines[k].instr.map(|i| i.flow_control())) {
                (Some(_), Some(iced_x86::FlowControl::IndirectCall)) => XrefKind::Call,
                (Some(_), Some(iced_x86::FlowControl::IndirectBranch)) => XrefKind::Jump,
                _ => kind,
            };
            if eff.matches(&filter) {
                rows.push((k, eff));
            }
        }
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for (_, kind) in &rows {
            *counts.entry(json!(kind).as_str().unwrap().to_string()).or_default() += 1;
        }
        let total = rows.len();
        let offset = prm.offset.unwrap_or(0).min(total);
        let limit = prm.limit.unwrap_or(100).clamp(1, 1000);
        let page = &rows[offset..(offset + limit).min(total)];
        let page_lines: Vec<disasm::Line> = page.iter().map(|&(k, _)| lines[k].clone()).collect();
        let mut wanted = disasm::referenced_addresses(p.as_ref(), &page_lines);
        wanted.push(target);
        // containing function, with the same detection as function_info (memoized by range)
        let mut found: Vec<(u64, u64, u64)> = Vec::new();
        let fn_starts: Vec<Option<u64>> = page
            .iter()
            .map(|&(k, _)| {
                let from = cands[k].0;
                if let Some(&(_, _, s)) = found.iter().find(|(lo, hi, _)| from >= *lo && from < *hi) {
                    return Some(s);
                }
                let code = codes.iter().find(|c| c.module.contains(from));
                match funcs::find(p.as_ref(), code.map(|c| c.as_ref()), from) {
                    Ok(f) if f.contains_query => {
                        found.extend(f.fragments.iter().map(|&(a, b)| (a, b, f.start)));
                        Some(f.start)
                    }
                    _ => None,
                }
            })
            .collect();
        wanted.extend(fn_starts.iter().flatten());
        let table = self.symbols.lock().unwrap().table_for(p.as_ref(), &wanted);
        let rendered = disasm::render(p.as_ref(), &page_lines, &table, syntax, &HashMap::new());
        let items: Vec<Value> = page
            .iter()
            .enumerate()
            .map(|(n, &(k, kind))| {
                let (from, _, via) = cands[k];
                json!({
                    "from": format::addr(from, ps),
                    "symbol": table.name(from),
                    "function": fn_starts[n].and_then(|s| table.name(s)),
                    "kind": kind,
                    "via": via.map(|v| table.name(v).unwrap_or_else(|| format::addr(v, ps))),
                    "text": rendered[n].text,
                })
            })
            .collect();
        Ok(json!({
            "target": format::addr(target, ps),
            "symbol": table.name(target),
            "size": size,
            "kind_filter": filter,
            "searched": searched,
            "counts": counts,
            "total": total,
            "offset": offset,
            "returned": items.len(),
            "has_more": offset + items.len() < total,
            "items": items,
            "note": "function = start of the containing function (same detection as function_info)",
        }))
    }

    pub fn do_make_signature(&self, prm: MakeSignatureParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let modules = p.modules()?;
        let home = modules
            .iter()
            .find(|m| m.contains(addr))
            .cloned()
            .ok_or_else(|| MemError::InvalidArg("signatures are built for addresses inside a module".into()))?;
        let scope_module = match &prm.module {
            Some(n) => address::lookup_module(&modules, n)?
                .ok_or_else(|| MemError::InvalidArg(format!("module '{n}' is not loaded")))?
                .clone(),
            None => home.clone(),
        };
        let (ranges, _) = pattern::resolve_ranges(p.as_ref(), &Scope { module: Some(scope_module.name.clone()), ..Default::default() })?;
        let mut images: Vec<(u64, u64)> = modules.iter().map(|m| (m.base, m.base + m.size)).collect();
        images.sort_unstable();
        let opts = SigOptions {
            min_len: prm.min_len.unwrap_or(8).clamp(1, 256),
            max_len: prm.max_len.unwrap_or(64).clamp(4, 256),
            wildcard_offsets: prm.wildcard_offsets.unwrap_or(false),
            wildcard_immediates: prm.wildcard_immediates.unwrap_or(false),
            max_back: prm.max_back.unwrap_or(8).min(64),
        };
        let code = self.code.get(p.as_ref(), &home)?;
        let is_code = code.exec_range(addr).is_some();

        // Instructions to sign: the target itself, or instructions referencing the data address.
        let targets: Vec<u64> = if is_code {
            vec![addr]
        } else {
            let idx = code.xref_index(p.as_ref(), &modules);
            let mut refs: Vec<(u8, u64)> = idx
                .query(addr, addr + 1)
                .iter()
                .map(|x| {
                    let rank = match x.kind {
                        XrefKind::Read | XrefKind::Write | XrefKind::ReadWrite => 0,
                        XrefKind::Address => 1,
                        _ => 2,
                    };
                    (rank, idx.base + x.from_off as u64)
                })
                .filter(|r| r.0 < 2)
                .collect();
            refs.sort_unstable();
            if refs.is_empty() {
                return Err(MemError::InvalidArg(format!(
                    "{} is data and no instruction in {} references it directly; sign the code that uses it instead",
                    format::addr(addr, ps),
                    home.name
                )));
            }
            refs.into_iter().take(10).map(|r| r.1).collect()
        };

        let mut best: Option<(sigs::Signature, u64)> = None;
        let mut last_err = None;
        for &t in &targets {
            let earlier: Vec<u64> = funcs::find(p.as_ref(), Some(&code), t)
                .map(|f| f.lines.iter().map(|l| l.address).filter(|&a| a < t).collect())
                .unwrap_or_default();
            match sigs::generate(p.as_ref(), t, &earlier, &ranges, &images, &opts) {
                Ok(sig) => {
                    // prefer signatures that start at the instruction itself, then shorter ones
                    let better = best.as_ref().is_none_or(|(b, bt)| {
                        ((sig.start != t), sig.pattern.len()) < ((b.start != *bt), b.pattern.len())
                    });
                    if better {
                        best = Some((sig, t));
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        let (sig, insn) = best.ok_or_else(|| last_err.unwrap_or_else(|| MemError::InvalidArg("no signature".into())))?;

        let sig_expr = format!("sig(\"{}\", \"{}\")", sig.pattern.display(), scope_module.name);
        let off = insn - sig.start;
        let insn_expr = if off == 0 { sig_expr.clone() } else { format!("{sig_expr}+0x{off:X}") };
        let (insn_i, insn_co) = sigs::instruction_at(p.as_ref(), insn)?;
        let data_expr = sigs::data_ref(&insn_i, &insn_co).map(|d| match d {
            DataRef::Rip { disp_offset, insn_len } => format!("rip({insn_expr}, 0x{disp_offset:X}, 0x{insn_len:X})"),
            DataRef::Abs32 { disp_offset } => format!("abs32({insn_expr}, 0x{disp_offset:X})"),
        });

        // verify the expressions against the live process
        let check = |e: &str| address::resolve(p.as_ref(), e, &[]).map(|r| r.address);
        let insn_ok = check(&insn_expr)?;
        if insn_ok != insn {
            return Err(MemError::Os(format!("internal error: {insn_expr} resolves to {insn_ok:#x}, expected {insn:#x}")));
        }
        let data_value = match &data_expr {
            Some(e) => Some(check(e)?),
            None => None,
        };
        if !is_code && data_value != Some(addr) {
            return Err(MemError::InvalidArg(format!(
                "the referencing instruction at {} does not compute {} statically",
                format::addr(insn, ps),
                format::addr(addr, ps)
            )));
        }

        // listing of the covered instructions
        let lines: Vec<disasm::Line> = sig
            .instructions
            .iter()
            .map(|i| {
                let mut b = vec![0u8; i.len()];
                let _ = p.read(i.ip(), &mut b);
                disasm::Line { address: i.ip(), bytes: b, kind: LineKind::Code, instr: Some(*i) }
            })
            .collect();
        let mut wanted = disasm::referenced_addresses(p.as_ref(), &lines);
        wanted.extend([addr, insn]);
        let table = self.symbols.lock().unwrap().table_for(p.as_ref(), &wanted);
        let rendered = disasm::render(p.as_ref(), &lines, &table, Syntax::Intel, &HashMap::new());
        let code_style: String = sig.pattern.bytes.iter().map(|b| format!("\\x{b:02X}")).collect();
        let mask: String = sig.pattern.masks.iter().map(|&m| if m == 0xFF { 'x' } else { '?' }).collect();
        let mut out = json!({
            "target": format::addr(addr, ps),
            "symbol": table.name(addr),
            "kind": if is_code { "code" } else { "data" },
            "pattern": sig.pattern.display(),
            "length": sig.pattern.len(),
            "code_style": { "bytes": code_style, "mask": mask },
            "unique_in": scope_module.name,
            "match": format::addr(sig.start, ps),
            "instruction": format::addr(insn, ps),
            "instruction_offset": off,
            "expression": if is_code {
                if addr == insn { insn_expr.clone() } else { format!("{insn_expr}+0x{:X}", addr - insn) }
            } else {
                data_expr.clone().unwrap_or_default()
            },
            "instruction_expression": insn_expr,
            "covered": disasm::listing(&rendered, true),
        });
        if is_code && let (Some(e), Some(v)) = (&data_expr, data_value) {
            out["data"] = json!({ "address": format::addr(v, ps), "symbol": table.name(v), "expression": e });
        }
        Ok(out)
    }

    pub fn do_write_value(&self, prm: WriteValueParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let ty = ValueType::parse(&prm.value_type, Some(1))?;
        let be = prm.big_endian.unwrap_or(false);
        let data = Self::encode_value(&p, ty, &prm.value, be, prm.null_terminate.unwrap_or(true))?;
        let type_name = Self::type_label(ty);
        let mut out = self.commit_write(&p, addr, &prm.address, Some(type_name.clone()), &data)?;
        let old = value::parse_hex_bytes(out["old_bytes"].as_str().unwrap()).unwrap_or_default();
        out["type"] = json!(type_name);
        out["old_value"] = Self::decode_elements(ty, &old, ps, be);
        out["new_value"] = Self::decode_elements(ty, &data, ps, be);
        Ok(out)
    }

    pub fn do_write_bytes(&self, prm: WriteBytesParams) -> CoreResult<Value> {
        let p = self.process()?;
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        let data = value::parse_hex_bytes(&prm.bytes)?;
        self.commit_write(&p, addr, &prm.address, None, &data)
    }

    pub fn do_undo_write(&self, prm: UndoWriteParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let rec = {
            let j = self.journal.lock().unwrap();
            match prm.id {
                Some(id) => j.get(id).cloned().ok_or_else(|| MemError::InvalidArg(format!("no write with id {id}")))?,
                None => j
                    .last_active(p.pid())
                    .cloned()
                    .ok_or_else(|| MemError::InvalidArg("no active writes for the attached process".into()))?,
            }
        };
        if rec.pid != p.pid() {
            return Err(MemError::InvalidArg(format!(
                "write #{} was made to pid {} ({}), but pid {} is attached",
                rec.id,
                rec.pid,
                rec.process,
                p.pid()
            )));
        }
        if rec.undone {
            return Err(MemError::InvalidArg(format!("write #{} was already undone", rec.id)));
        }
        let mut current = vec![0u8; rec.new_bytes.len()];
        p.read(rec.address, &mut current)?;
        let changed = current != rec.new_bytes;
        if changed && !prm.force.unwrap_or(false) {
            return Err(MemError::InvalidArg(format!(
                "memory at {} changed since write #{} (now {}, written {}); pass force=true to restore the original bytes anyway",
                format::addr(rec.address, ps),
                rec.id,
                value::hex_bytes(&current),
                value::hex_bytes(&rec.new_bytes)
            )));
        }
        let outcome = p.write_force(rec.address, &rec.old_bytes)?;
        self.journal.lock().unwrap().mark_undone(rec.id, ps);
        Ok(json!({
            "undone": rec.id,
            "address": format::addr(rec.address, ps),
            "restored_bytes": value::hex_bytes(&rec.old_bytes),
            "replaced_bytes": value::hex_bytes(&current),
            "forced": changed,
            "protection_lifted": !outcome.protection_changes.is_empty(),
        }))
    }

    pub fn do_list_writes(&self, prm: ListWritesParams) -> CoreResult<Value> {
        let current = self.attached.lock().unwrap().as_ref().map(|p| (p.pid(), p.pointer_size()));
        let all = prm.all_processes.unwrap_or(false);
        if !all && current.is_none() {
            return Err(MemError::NotAttached);
        }
        let include_undone = prm.include_undone.unwrap_or(true);
        let j = self.journal.lock().unwrap();
        let items: Vec<Value> = j
            .records()
            .iter()
            .rev()
            .filter(|r| all || Some(r.pid) == current.map(|c| c.0))
            .filter(|r| include_undone || !r.undone)
            .map(|r| {
                let ps = match current {
                    Some((pid, ps)) if pid == r.pid => ps,
                    _ => 8,
                };
                r.to_json(ps)
            })
            .collect();
        let mut page = format::page(&items, prm.offset, prm.limit);
        page["journal_file"] = json!(j.file().map(|f| f.display().to_string()));
        Ok(page)
    }

    pub fn do_read_bytes(&self, prm: ReadBytesParams) -> CoreResult<Value> {
        let p = self.process()?;
        let ps = p.pointer_size();
        let addr = self.resolve(&p, &prm.address, &prm.offsets)?;
        if prm.size == 0 || prm.size > MAX_READ_BYTES {
            return Err(MemError::InvalidArg(format!("size must be 1..={MAX_READ_BYTES}")));
        }
        let bytes = p.read_partial(addr, prm.size);
        let unreadable = bytes.iter().filter(|b| b.is_none()).count();
        if unreadable == bytes.len() {
            return Err(MemError::Read { addr, size: prm.size, reason: p.explain_unreadable(addr) });
        }
        let hex: String = bytes
            .iter()
            .map(|b| b.map(|b| format!("{b:02X}")).unwrap_or_else(|| "??".into()))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(json!({
            "address": format::addr(addr, ps),
            "size": prm.size,
            "unreadable_bytes": unreadable,
            "hex": hex,
            "dump": format::hexdump(addr, &bytes, ps),
        }))
    }
}

#[tool_router]
impl MemoryServer {
    #[tool(description = "List running processes (pid, parent pid, name, threads). Paginated.")]
    async fn list_processes(
        &self,
        Parameters(p): Parameters<ListProcessesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_processes(p))
    }

    #[tool(description = "Attach to a process by pid or executable name. Replaces any previous attachment. \
Returns pid, path, arch (x86/x64), pointer size, write access and main module base.")]
    async fn attach(&self, Parameters(p): Parameters<AttachParams>) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_attach(p))
    }

    #[tool(description = "Detach from the current process.")]
    async fn detach(&self) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_detach())
    }

    #[tool(description = "Info about the attached process: pid, path, arch, bits, pointer size, write access, main module.")]
    async fn process_info(&self) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_process_info())
    }

    #[tool(description = "List modules (DLL/EXE) loaded in the attached process with base, size and arch. \
For 32-bit (WOW64) processes only the 32-bit address space (below 4 GiB) is visible. Paginated.")]
    async fn list_modules(
        &self,
        Parameters(p): Parameters<ListModulesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_modules(p))
    }

    #[tool(description = "List memory regions of the attached process (base, size, protection rwx, kind, owning module). \
Filter by protection flags, kind or module. Paginated.")]
    async fn list_regions(
        &self,
        Parameters(p): Parameters<ListRegionsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_regions(p))
    }

    #[tool(description = "Read typed value(s) at an address: integers, floats, bool, ptr, bytes, utf8/utf16 strings. \
Returns value plus hex. Use `count` for arrays.")]
    async fn read_value(
        &self,
        Parameters(p): Parameters<ReadValueParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_read_value(p))
    }

    #[tool(description = "Write a typed value (ints, floats, bool, ptr, bytes, utf8/utf16; arrays) at an address \
expression. Read-only/executable pages are made writable temporarily and restored. Returns old and new value, \
read-back verification and a write_id for undo_write.")]
    async fn write_value(
        &self,
        Parameters(p): Parameters<WriteValueParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_write_value(p))
    }

    #[tool(description = "Write raw bytes (hex) at an address expression, e.g. to patch code with NOPs. \
Protection is lifted temporarily; returns old bytes, verification and a write_id for undo_write.")]
    async fn write_bytes(
        &self,
        Parameters(p): Parameters<WriteBytesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_write_bytes(p))
    }

    #[tool(description = "Undo a write by id (default: the latest active write in the attached process) by restoring \
the original bytes. Refuses if the memory changed since the write unless force=true.")]
    async fn undo_write(
        &self,
        Parameters(p): Parameters<UndoWriteParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_undo_write(p))
    }

    #[tool(description = "List the write journal (newest first): id, address, old/new bytes, protection changes, undone flag. \
By default only writes to the attached process.")]
    async fn list_writes(
        &self,
        Parameters(p): Parameters<ListWritesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_writes(p))
    }

    #[tool(description = "Define or replace a struct template: ordered fields with type (value types, another struct \
embedded by value, *Struct pointer), optional offset, length, count (arrays). Missing offsets get C-like natural \
alignment for the target bitness. Templates are saved to a JSON file. Returns the computed layout.")]
    async fn define_struct(
        &self,
        Parameters(p): Parameters<DefineStructParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_define_struct(p))
    }

    #[tool(description = "List struct templates, or show one (definition + layout for the attached process' bitness).")]
    async fn list_structs(
        &self,
        Parameters(p): Parameters<ListStructsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_structs(p))
    }

    #[tool(description = "Delete a struct template (refused while other templates use it).")]
    async fn delete_struct(
        &self,
        Parameters(p): Parameters<DeleteStructParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_delete_struct(p))
    }

    #[tool(description = "Read a struct (template name or inline fields) at an address expression in one call: \
every field with offset, address and value; nested structs and arrays; *Struct pointer fields are followed \
up to `depth` levels. Unreadable fields carry an `error`. Use `count` for arrays of structs.")]
    async fn read_struct(
        &self,
        Parameters(p): Parameters<ReadStructParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_read_struct(p))
    }

    #[tool(description = "Write struct fields by path ({\"health\": 100, \"pos.x\": 1.5, \"items[2]\": 7}) using a template \
or inline fields. All values are validated before anything is written; each field is a separate journaled write \
(undo_write works per field).")]
    async fn write_struct(
        &self,
        Parameters(p): Parameters<WriteStructParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_write_struct(p))
    }

    #[tool(description = "Scan memory for a byte pattern (IDA/CE notation, nibble wildcards, \\x..+mask, raw hex, \
str:/wstr: strings) in a module, a PE section (.text/.rdata/.data), an address range or the whole process, \
optionally filtered by protection (x = code). Returns match addresses with module+offset and bytes.")]
    async fn aob_scan(
        &self,
        Parameters(p): Parameters<AobScanParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_aob_scan(p)).await
    }

    #[tool(description = "Resolve a signature to one address: the unique (or index-th) match + offset, then optionally \
mode=rip (relative operand: addr + insn_len + disp32), abs32 (x86 absolute operand) or ptr (dereference). Returns \
the address, a trace and an equivalent expression usable in read_value/write_value (e.g. rip(sig(\"..\", \"game.exe\")+3)).")]
    async fn aob_resolve(
        &self,
        Parameters(p): Parameters<AobResolveParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_aob_resolve(p))
    }

    #[tool(description = "Start a value scan (first scan) for a numeric type: condition exact (default with `value`), \
not, range, bigger, smaller or unknown (snapshot). Default scope: writable, non-mapped memory of the whole process \
(narrow with module/section/start/end). Returns scan_id, candidate count and a preview.")]
    async fn scan_start(
        &self,
        Parameters(p): Parameters<ScanStartParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_scan_start(p)).await
    }

    #[tool(description = "Narrow a scan (next scan) by comparing current values with the previous scan: changed, \
unchanged, increased, decreased, increased_by, decreased_by, or with a value: exact, not, range, bigger, smaller.")]
    async fn scan_next(
        &self,
        Parameters(p): Parameters<ScanNextParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_scan_next(p)).await
    }

    #[tool(description = "Page through scan candidates: address, module+offset, current value and value at the last scan.")]
    async fn scan_results(
        &self,
        Parameters(p): Parameters<ScanResultsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_scan_results(p))
    }

    #[tool(description = "Close a scan and free its memory / temporary file.")]
    async fn scan_close(
        &self,
        Parameters(p): Parameters<ScanCloseParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_scan_close(p))
    }

    #[tool(description = "List open scans with type, scope, candidate count, history of conditions and storage used.")]
    async fn scan_list(&self) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_scan_list())
    }

    #[tool(description = "Freeze a value in the background: rewrite it every interval_ms when it changes \
(mode exact), only when it drops (no_decrease) or only when it rises (no_increase). Default value: the current one. \
Pointer chains are re-resolved each tick. Returns freeze_id.")]
    async fn freeze_value(
        &self,
        Parameters(p): Parameters<FreezeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_freeze(p))
    }

    #[tool(description = "Stop a freeze (or all) and optionally restore the value from before the freeze.")]
    async fn unfreeze(
        &self,
        Parameters(p): Parameters<UnfreezeParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_unfreeze(p))
    }

    #[tool(description = "List freezes with address, value, mode, writes (restorations), errors and running state.")]
    async fn list_freezes(&self) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_freezes())
    }

    #[tool(description = "Watch a value in the background: sample every interval_ms and record each change \
(seq, time, value) in a ring buffer. Read changes with watch_read. Returns watch_id and the initial value.")]
    async fn watch_value(
        &self,
        Parameters(p): Parameters<WatchParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_watch(p))
    }

    #[tool(description = "Read recorded changes of a watch (seq >= since; pass next_since from the previous call \
to get only new ones), plus current value, dropped count and running state.")]
    async fn watch_read(
        &self,
        Parameters(p): Parameters<WatchReadParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_watch_read(p))
    }

    #[tool(description = "Stop a watch (or all).")]
    async fn unwatch(
        &self,
        Parameters(p): Parameters<UnwatchParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_unwatch(p))
    }

    #[tool(description = "List watches with address, type, current value, number of changes and running state.")]
    async fn list_watches(&self) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_list_watches())
    }

    #[tool(description = "Pointer scan: find static pointer chains (module+offset → [..]+o1 → … → target) to an \
address, e.g. a value found with scan_*. Builds an index of all pointers, then searches backwards up to max_depth \
levels with max_offset per level. Returns ptr_scan_id and the shortest chains first.")]
    async fn pointer_scan(
        &self,
        Parameters(p): Parameters<PointerScanParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_pointer_scan(p)).await
    }

    #[tool(description = "Page through pointer chains; each has base, offsets, a ready-to-use expression and \
(verify=true) the address it resolves to now and whether that is still the target.")]
    async fn pointer_scan_results(
        &self,
        Parameters(p): Parameters<PointerResultsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_pointer_results(p))
    }

    #[tool(description = "Re-check pointer chains in the attached process and keep only those that resolve to the \
target — after a restart pass the new target address (found again with scan_*). Repeat across restarts until \
only stable chains remain.")]
    async fn pointer_rescan(
        &self,
        Parameters(p): Parameters<PointerRescanParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_pointer_rescan(p)).await
    }

    #[tool(description = "Close a pointer scan and free its chains.")]
    async fn pointer_scan_close(
        &self,
        Parameters(p): Parameters<PointerCloseParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_pointer_close(p))
    }

    #[tool(description = "List pointer scans with target, chain count and rescan history.")]
    async fn pointer_scan_list(&self) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_pointer_list())
    }

    #[tool(description = "Disassemble x86/x64 code at an address expression: listing with module+offset, bytes and \
instructions (intel by default; masm, nasm, att), branch targets and memory operands shown as symbols \
(module exports or module+offset), `-> kernel32.dll!X` comments for calls through the import table. \
Use count / size / until_ret to bound it and `next` to continue. details=true adds structured data.")]
    async fn disassemble(
        &self,
        Parameters(p): Parameters<DisassembleParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_disassemble(p))
    }

    #[tool(description = "Find the function containing an address: start/end/size, how the boundaries were found \
(pdata = exact x64 unwind table, call_target/export/padding/section_start = heuristics), fragments (cold code), \
direct calls with symbols and indirect calls with their current targets.")]
    async fn function_info(
        &self,
        Parameters(p): Parameters<FunctionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_function_info(p)).await
    }

    #[tool(description = "Disassemble the whole function containing an address, with loc_ labels for jump targets \
inside it and all its fragments. Same syntax options as disassemble.")]
    async fn disassemble_function(
        &self,
        Parameters(p): Parameters<DisassembleFunctionParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_disassemble_function(p)).await
    }

    #[tool(description = "List functions of a module (x64 .pdata entries, call targets from a code sweep, exports) \
with symbol and source; filter by name. Paginated.")]
    async fn list_functions(
        &self,
        Parameters(p): Parameters<ListFunctionsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_list_functions(p)).await
    }

    #[tool(description = "Find code that references an address: calls, jumps, reads, writes (incl. read-modify-write) \
and address-taking (lea / immediates), also through pointer slots holding the address (import table → calls to \
kernel32.dll!X). Searches the target's module and the main exe by default (modules: [\"*\"] for all; each module is \
indexed once and cached). Each hit has the instruction text and the containing function.")]
    async fn find_xrefs(
        &self,
        Parameters(p): Parameters<FindXrefsParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_find_xrefs(p)).await
    }

    #[tool(description = "Make a unique AOB signature for an address so it can be found again after updates/ASLR: \
address and branch bytes become ??, the pattern grows until unique in the module (optionally starting a few \
instructions earlier). For code returns sig(...)+off; for a static data address it signs an instruction that \
references it and returns rip(...)/abs32(...) that computes the data address. Expressions are verified live.")]
    async fn make_signature(
        &self,
        Parameters(p): Parameters<MakeSignatureParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        let s = self.clone();
        blocking(move || s.do_make_signature(p)).await
    }

    #[tool(description = "Evaluate an address expression (module+offset, exports, [..] dereference, arithmetic, pointer-chain offsets) and return the address, its module+offset form, region protection and a step-by-step trace of every module lookup and dereference. Use it to debug pointer chains.")]
    async fn resolve_address(
        &self,
        Parameters(p): Parameters<ResolveAddressParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_resolve_address(p))
    }

    #[tool(description = "Read raw bytes and return a hexdump. Unreadable bytes are shown as ??.")]
    async fn read_bytes(
        &self,
        Parameters(p): Parameters<ReadBytesParams>,
    ) -> std::result::Result<CallToolResult, ErrorData> {
        respond(self.do_read_bytes(p))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for MemoryServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("memory-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }
}
