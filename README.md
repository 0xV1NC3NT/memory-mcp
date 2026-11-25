# memory-mcp

A local MCP server (stdio) for reading, writing and searching the memory of Windows processes (x64 and x86/WOW64).

## Build

```powershell
cargo build --release
```

Binary: `target\release\memory-mcp.exe`. To work with processes running as administrator, the server must run as administrator too.

## Connecting to Claude Code

`.mcp.json` in the root of your project:

```json
{
  "mcpServers": {
    "memory": { "command": "D:/Dev/memory-mcp/target/release/memory-mcp.exe" }
  }
}
```

or `claude mcp add memory -- D:/Dev/memory-mcp/target/release/memory-mcp.exe`.

## Connecting to opencode

In `~/.config/opencode/opencode.json` (global) or a project's `opencode.json`, under `mcp` (this format is accepted by both opencode 1.x and OpenCode Desktop 2.x):

```json
"memory": {
  "type": "local",
  "command": ["C:/Users/<user>/.local/bin/memory-mcp.exe"],
  "enabled": true
}
```

Check: `opencode mcp list` → `✓ memory connected`. OpenCode Desktop picks up config changes by itself; open windows can reconnect the server with `/mcps` if needed.

- Point clients at a copy of the binary outside `target\`: clients (including the OpenCode Desktop background service) keep the server running, and Windows does not let `cargo build` overwrite an exe that is in use.
- **Do not put the exe under `%LOCALAPPDATA%`**: OpenCode Desktop 2.3 does not start local MCP servers from there — the server "exits with code 1" and the message "The system cannot find the path specified" (shown as CP866 mojibake on a Russian system). The same exe works from `~/.local/bin`, `D:\…` or `target\`.

After rebuilding:

```powershell
Copy-Item target\release\memory-mcp.exe $env:USERPROFILE\.local\bin\memory-mcp.exe -Force
```

(if the copy is in use, reconnect the server in the client or restart the client).

## Tools

| Tool | What it does |
|---|---|
| `list_processes` | list processes, filter by name or pid |
| `attach` / `detach` | attach by pid or name |
| `process_info` | pid, path, bitness, pointer size, write access, main module |
| `list_modules` | modules with base, size and architecture |
| `list_regions` | memory regions, filters by `rwx`, kind and module |
| `resolve_address` | evaluates an address expression: address, `module+offset`, region protection, dereference trace |
| `read_value` | i8…u64, f32, f64, bool, ptr, bytes, utf8, utf16; arrays via `count` |
| `read_bytes` | hexdump; unreadable bytes are shown as `??` |
| `write_value` | write a typed value or an array; for `ptr` the value may be an address expression |
| `write_bytes` | write hex bytes (`DE AD`, `DEAD`, `\xDE\xAD`, `0xDE, 0xAD`) |
| `undo_write` | undo a write by id (the latest by default); refused if the memory changed since the write unless `force` is passed |
| `list_writes` | write journal, newest first |
| `define_struct` | create or replace a struct template; returns the layout and sizes for x86 and x64 |
| `list_structs` | list templates, or one template with its layout |
| `delete_struct` | delete a template (refused while other templates use it) |
| `read_struct` | read a struct by template or inline fields: nested structs, arrays, following `*Struct` pointers |
| `write_struct` | write fields by path `health`, `pos.x`, `items[2]`; each field is a separate journaled write |
| `aob_scan` | search for a signature in a module, a section, a range or the whole process |
| `aob_resolve` | signature → address (`+offset`, `rip`, `abs32`, `ptr`) and a ready-to-use expression |
| `scan_start` | first value scan: `exact`, `not`, `range`, `bigger`, `smaller`, `unknown` |
| `scan_next` | narrow by comparing with the previous scan: `changed`, `unchanged`, `increased`, `decreased`, `increased_by`, `decreased_by`, or by value |
| `scan_results` | page of candidates: address, `module+offset`, current value and value at the previous scan |
| `scan_close` / `scan_list` | close a scan / list open scans with their condition history |
| `freeze_value` / `unfreeze` / `list_freezes` | freeze a value in the background (`exact`, `no_decrease`, `no_increase`) |
| `watch_value` / `watch_read` / `unwatch` / `list_watches` | watch a value: a timestamped log of changes |
| `pointer_scan` | find static pointer chains `module+base → offsets → address` |
| `pointer_scan_results` | page of chains with a ready-to-use expression and a check in the current process |
| `pointer_rescan` | drop chains that no longer lead to the target (also after a restart) |
| `pointer_scan_close` / `pointer_scan_list` | close / list pointer scans with their history |
| `disassemble` | x86/x64 disassembly at an address expression (iced-x86), symbols from exports |
| `function_info` / `disassemble_function` | function bounds from any address inside it, calls; full listing with `loc_` labels |
| `list_functions` | functions of a module (x64 `.pdata`, `call` targets, exports) with a name filter |
| `find_xrefs` | who calls / jumps to / reads / writes / takes the address of a target (also through the IAT), with the function and instruction text |
| `make_signature` | unique signature for code or static data + verified `sig(...)`, `rip(...)`, `abs32(...)` expressions |

## Structs

```json
{ "name": "Player", "fields": [
  { "name": "health", "type": "i32" },
  { "name": "name",   "type": "utf8", "length": 16 },
  { "name": "pos",    "type": "Vec3" },
  { "name": "items",  "type": "u16", "count": 4 },
  { "name": "next",   "type": "*Player" },
  { "name": "flags",  "type": "u32", "offset": "0x80" }
] }
```

- Field type: any value type, the name of another template (embedded by value), or `*Name` / `ptr:Name` (pointer to a struct).
- `offset` is optional: without it the field is placed after the previous one with natural alignment, like a C compiler does. The layout follows the process bitness: pointers are 4 or 8 bytes. `packed: true` turns alignment off.
- `read_struct` follows pointer fields up to `depth` levels (default 1). Unreadable fields get an `error`; the rest are still read.
- `write_struct` validates and encodes all values first and only then writes; fields are written in the order given.
- Templates are saved to `%LOCALAPPDATA%\memory-mcp\structs.json`. Change the path with `--structs <file>` or `MEMORY_MCP_STRUCTS`; `--no-structs-file` keeps them in memory only. A corrupt file is never overwritten.

## Writing memory

- Writing is always allowed. Read-only or execute-only pages (`r--`, `r-x`) are made writable temporarily and their protection is restored afterwards. The instruction cache is flushed for executable pages.
- After a write the value is read back; the result is the `verified` field.
- The original bytes are saved before every write. The journal is kept in memory (for undo) and appended to a JSONL file: `%LOCALAPPDATA%\memory-mcp\writes.jsonl` by default. Change the path with `--journal <file>` or `MEMORY_MCP_JOURNAL`; `--no-journal` disables the file.
- Undo is bound to the process: a write can only be undone in the same process it was made in.

## Address expressions

Accepted by every tool with an `address` parameter.

| Form | Example |
|---|---|
| hex | `0x7FF6A1B2C3D0`, `7FF6A1B2C3D0h`, `1A2B`, ``00007ff6`a1b2c3d0`` |
| dec | `#6699` |
| module + offset | `game.exe+0x1A2B`, `game+1A2B`, `"my mod.dll"+10` |
| export / ordinal | `kernel32.dll!CreateFileW`, `mod.dll!#12` (forwarders are resolved) |
| dereference | `[[game.exe+0x10]+0x20]+0x30` |
| arithmetic | `+ - *`, parentheses, unary minus |
| chain as a list | `address: "game.exe+0x10", offsets: [0x20, "-8", 48]` |
| signature | `sig("48 8B 05 ?? ?? ?? ??", game.exe)`, `sig("\x48\x8B\x00", "xx?", "game.exe", ".text")` |
| RIP-relative / relative branch | `rip(sig(...), 3, 7)`: address + instruction length + disp32 at the given offset; defaults 3 and 7, for `E8`/`E9` use `rip(addr, 1, 5)` |
| absolute operand (x86) | `abs32(sig("A1 ?? ?? ?? ??", game.exe), 1)` |

- A bare word is a module if one with that name is loaded, otherwise a hex number (`dead` vs `dead.dll`, like Cheat Engine). Numbers inside function arguments are hex too.
- In `offsets`, JSON numbers are decimal and strings are expressions (hex by default). For each offset: `addr = [addr] + offset`.
- `sig()` requires exactly one match; with several, the error shows how many and the first addresses.

## Signatures (AOB)

| Notation | Example |
|---|---|
| IDA | `48 8B ?? ?? 05`, `48 8B ? ? 05` |
| Cheat Engine | `48 8B * * 05` |
| nibble wildcards | `4? 8B ?5` |
| code + mask | `\x48\x8B\x00\x00\x05` + `mask: "xx??x"` |
| raw hex | `488B????05`, `0x48, 0x8B` |
| strings | `str:"Health"` (UTF-8), `wstr:"Health"` (UTF-16LE) |

- `aob_scan` searches a module, a PE section (`.text`, `.rdata`, `.data`), a `start`/`end` range or the whole process, with a protection filter (`x` = code only) and alignment. Results are sorted by address, `limit` up to 10000, with a `truncated` flag.
- `aob_resolve` turns the single (or `index`-th) match into an address: `+offset`, then `mode` = `address` | `rip` | `abs32` | `ptr`. Returns a trace and an equivalent expression for `read_value`/`write_value`.
- Search: the rarest exact byte of the pattern is found with `memchr`, the rest is checked against the mask; memory is read in 1 MiB chunks in parallel (rayon), and matches across chunk boundaries are not lost. About 4 GiB/s on 1 GiB of data (`cargo test --release --test stage5 -- --ignored --nocapture`).

## Value scanning (Cheat Engine style)

1. `scan_start` with a type and value (`{"type": "i32", "value": 100}`), or `condition: "unknown"` if the value is unknown.
2. Change the value in the program.
3. `scan_next` with `exact` and the new value, or with `changed` / `increased` / `decreased_by` … — repeat until few candidates remain.
4. `scan_results` → `write_value` at the address found.

- Types: numeric (`i8`…`u64`, `f32`, `f64`, `bool`, `ptr`). For bytes and strings use `aob_scan`.
- Default scope: writable (`w`) memory without mapped files, as in CE. Narrow it with `module`, `section`, `start`/`end`; widen it with `protection: ""`, `include_mapped: true`.
- Default alignment is the type's natural alignment, at most 4 (`alignment: 1` for an unaligned search).
- Floats: `float_mode` = `rounded` (default; compared after rounding to the number of decimals you typed: `1.55` finds `1.5499999`), `truncated`, `exact` (the same `f32`/`f64`), or `tolerance`.
- Relative conditions compare with the previous scan, not the first one.
- Candidates are stored in 1 MiB chunks: a list of "offset + value", or a snapshot with a bitmap for dense results (whichever is smaller). Beyond `max_memory_mb` (default 512) data spills to a temporary file that is deleted on `scan_close` and on the next scan.
- A scan is bound to its process; up to 16 scans can be open at once.
- Speed on 1 GiB (release): `exact` ~0.25 s; `unknown` in RAM: 0.2 s first scan and 1.7 s next scan; when spilling to disk the next scan is disk-bound (6–12 s). Benchmark: `cargo test --release --test stage6 -- --ignored --nocapture`.

## Freeze and watch

- `freeze_value` checks the value every `interval_ms` (default 100, minimum 5 ms) and rewrites it: `exact` on any change, `no_decrease` only when it drops below the given value, `no_increase` only when it rises above it. Without `value` the current value is frozen. `unfreeze` with `restore: true` puts back the value from before the freeze. Individual rewrites are not journaled.
- `watch_value` polls a value and records every change (`seq`, `t_ms`, value) in a ring buffer (`max_events`, default 1000). The initial value is event #0. `watch_read` with `since` = `next_since` from the previous response returns only new changes. Changes shorter than the polling interval can be missed.
- If the address is given with `[..]` or `offsets`, it is re-resolved on every tick (`re_resolve`), so a freeze survives the object moving.
- Background tasks stop on `unfreeze`/`unwatch`, `detach`, `attach` to another process and when the process exits (`stop_reason: "process exited"`). Up to 64 tasks at once.

## Disassembly

```text
testbed.exe+0x52A0  8B 05 7E ED 02 00  mov eax, dword ptr [testbed.exe+0x34024]
testbed.exe+0x52A6  FF C8              dec eax
testbed.exe+0x52A8  89 05 76 ED 02 00  mov dword ptr [testbed.exe+0x34024], eax
testbed.exe+0x52AE  C3                 ret
KERNEL32.DLL!Sleep:
KERNEL32.DLL!Sleep  48 FF 25 61 98 05 00  jmp qword ptr [KERNEL32.DLL+0x8A6B8]  ; -> KERNELBASE.dll!Sleep
```

- `disassemble(address, count, size, until_ret, syntax, show_bytes, details)`: the address is any address expression (`kernel32.dll!Sleep`, `sig(...)`, pointer chains).
- Syntax: `intel` (default), `masm`, `nasm`, `att`. Operand size is always shown (`dword ptr`); RIP-relative operands are shown as the final address.
- Addresses are labeled with module exports (`module!name`, with a label line at the entry point) or `module+0xOFF`; `call/jmp [IAT]` gets a `; -> module!function` comment.
- Invalid bytes are shown as `db 0x..`, unreadable memory stops the listing (`stopped_by`), and `next` is the address to continue from. `details: true` adds the flow type, branch target and memory operand address.

### Functions

- **x64 `.pdata`** (the unwind table) gives exact bounds; chained unwind entries put a function's "cold" fragments together (`source: pdata_chained`, `fragments` list).
- **x64 leaf functions and all of x86** have no `.pdata` entries. The start is the nearest known start (a `call` target from a sweep of the module's code, or an export), or the 16-byte-aligned address after `int3` padding / the start of the code section, provided decoding from it reaches the address; the end comes from a control-flow traversal (conditional branches, jumps inside the function; a jump to another function counts as a tail call), never past the next known start. The method is given in `source`.
- `function_info` returns direct calls with symbols and indirect calls with their current target (`"currently": "ntdll.dll!wcslen"`). An address outside a recognizable function (data, padding) is an error.
- The module code index (`.pdata`, `call` targets, exports) is built once per module and cached: KERNELBASE.dll (1.7 MiB of code) takes ~20 ms (`cargo run --release --example code_index_bench -- <pid>`).

### Cross-references

```text
testbed.exe+0x47C0 read_write in testbed.exe+0x3000  xchg dword ptr [testbed.exe+0x34024], eax
testbed.exe+0x52A0 read       in testbed.exe+0x52A0  mov eax, dword ptr [testbed.exe+0x34024]
testbed.exe+0x52A8 write      in testbed.exe+0x52A0  mov dword ptr [testbed.exe+0x34024], eax
testbed.exe+0xBC5B call       via testbed.exe+0x24050  call qword ptr [testbed.exe+0x24050]   ← kernel32!GetStdHandle
```

- `find_xrefs(target, size, kind, modules, via_pointers)`: `kind` is `any`, `call`, `jump`, `code`, `read`, `write` (including read-modify-write), `access`, `address` (`lea`, an immediate address). `size` sets the target range (a field or a whole struct).
- The index is built by a linear sweep of the module's code that re-synchronizes at known function starts (data inside `.text` cannot desync decoding); access is classified with iced's `instr_info`. Built once per module: testbed.exe (~40k instructions) takes ~50–70 ms.
- `via_pointers` (on by default): slots inside the module that hold the target address (import table, vtables) and the instructions that read them; `call [slot]` counts as a `call` with a `via` field.
- By default the target's module and the main exe are searched; `modules: ["*"]` searches all modules. Each reference's `function` is the start of the containing function (same logic as `function_info`).

### Signature generation

```json
{ "address": "testbed.exe+0x34024" }   →
"pattern":    "8B 05 ?? ?? ?? ?? FF C8",
"expression": "rip(sig(\"8B 05 ?? ?? ?? ?? FF C8\", \"testbed.exe\"), 0x2, 0x6)"
```

- Bytes that encode addresses become `??`: RIP-relative and absolute displacements, relative branches, immediates pointing into modules (via iced `ConstantOffsets`). Opcodes, registers and small field offsets are kept (`wildcard_offsets` / `wildcard_immediates` mask those too).
- The pattern grows by whole instructions until it is unique in the module; if the instruction itself cannot be made unique, starts at a few earlier instructions of the function are tried (`max_back`), giving `sig(...)+0xOFF`.
- For a **data** address, an instruction that reads or writes it is signed (taken from the xref index), and a `rip(...)` (x64) or `abs32(...)` (x86) expression that computes the data address is returned. For code that references data, the same expression is in the `data` field.
- Both expressions are verified against the live process before the response. The `\x..` + `xx??` mask form is included as well.
- Test: signatures taken in one run of the test target still find `tick`, `take_damage` and `HEALTH` after a restart (different addresses because of ASLR).

## Pointer chains

Dynamic objects (the player, the inventory) live on the heap and move on every run. A pointer scan finds a path from a static address in a module to the value:

1. Find the value's address (`scan_start` / `scan_next`).
2. `pointer_scan` with `target` = that address (`max_depth` 4 and `max_offset` 0x1000 by default).
3. Restart the program, find the value again, `attach`, and call `pointer_rescan` with the new `target`. Repeat 1–2 times: only stable chains remain.
4. Use a chain's `expression` (e.g. `[["game.exe"+0x41240]+0x18]+0x30`) or its `base` + `offsets` in `read_value`, `write_value`, `freeze_value`.

- Index: every aligned pointer-sized value in image and writable memory that points into readable memory, sorted by value. Built in parallel.
- The search goes backwards from the target level by level: the closest values and the paths with the smallest total offset come first. An address appears at most once per level and a static base once per depth, so a short coincidental path cannot hide a structural one.
- Chains are bound to the module, not to the pid, so they survive restarts. `modules` limits the allowed bases; `max_results` / `max_nodes` limit the work (`truncated` is set when they trigger).
- On the test target: ~130–150k pointers are indexed in ~10 ms and a depth-5 search takes a few ms; after a restart, rescan keeps 43 of 304 (x64) and 14 of 366 (x86) chains. Statistics: `cargo test --release --test stage8 -- --ignored --nocapture`.

## Tests

```powershell
rustup target add i686-pc-windows-msvc
cargo test
```

The tests build the `testbed` target for x64 and x86 and check the tools on both bitnesses, plus an end-to-end MCP test over stdio.

Checking that the code still builds for Linux (there is no backend yet, but nothing outside `platform/` and `binfmt` should be Windows-specific):

```powershell
rustup target add x86_64-unknown-linux-gnu
cargo clippy --target x86_64-unknown-linux-gnu --all-targets
```

## Platforms

The Windows backend is implemented (x64 server; x64 and x86/WOW64 targets). All OS access goes through the `ProcessMemory` trait in `src/platform/`, and module format parsing through `src/binfmt.rs` (PE is done; ELF is recognized and currently returns "not supported"). What a Linux backend needs is described at the top of `src/platform/mod.rs`.
