//! Test target for memory-mcp integration tests. Build for x64 and x86:
//!   cargo build -p testbed --target x86_64-pc-windows-msvc
//!   cargo build -p testbed --target i686-pc-windows-msvc
//!
//! On start prints one JSON line with addresses of known values, then reads commands from stdin:
//!   get <field> | set <field> <value> | dump | quit
//! Fields: health (i32), gold (u64), speed (f32), precision (f64), player_health (i32), player_armor (i32);
//! get-only: pos_x, pos_z, item2, player_name, sidekick_health

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU16, AtomicU32, AtomicU64, Ordering::Relaxed, Ordering::SeqCst};

static HEALTH: AtomicI32 = AtomicI32::new(100);
static GOLD: AtomicU64 = AtomicU64::new(123_456_789_012);
static SPEED: AtomicU32 = AtomicU32::new(1.5f32.to_bits());
static PRECISION: AtomicU64 = AtomicU64::new(3.14159265358979f64.to_bits());
static NAME: [u8; 16] = *b"TestbedPlayer\0\0\0";
static WNAME: [u16; 8] = [b'T' as u16, b'e' as u16, b's' as u16, b't' as u16, b'b' as u16, b'e' as u16, b'd' as u16, 0];
/// Unique byte pattern for AOB tests: "MEMMCP" DE AD BE EF 13 37 ?? ?? 22 33
static SIGNATURE: [u8; 16] = [0x4D, 0x45, 0x4D, 0x4D, 0x43, 0x50, 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0x00, 0x11, 0x22, 0x33];

/// Fake code for signature tests, filled at startup:
/// CA FE BA BE 51 6E | 48 8B 05 <disp32 → HEALTH> (mov rax,[rip+disp]) | A1 <abs32 = &HEALTH> (mov eax,[abs]) | 90 90
static mut PATCH: [u8; 20] =
    [0xCA, 0xFE, 0xBA, 0xBE, 0x51, 0x6E, 0x48, 0x8B, 0x05, 0, 0, 0, 0, 0xA1, 0, 0, 0, 0, 0x90, 0x90];

fn fill_patch() {
    unsafe {
        let base = (&raw mut PATCH) as *mut u8;
        let insn = base.add(6) as i64;
        let health = &HEALTH as *const AtomicI32 as i64;
        let disp = (health - (insn + 7)) as i32;
        std::ptr::copy_nonoverlapping(disp.to_le_bytes().as_ptr(), base.add(9), 4);
        std::ptr::copy_nonoverlapping((health as u32).to_le_bytes().as_ptr(), base.add(14), 4);
    }
}

#[repr(C)]
struct Vec3 {
    x: AtomicU32, // f32 bits
    y: AtomicU32,
    z: AtomicU32,
}

impl Vec3 {
    fn new(x: f32, y: f32, z: f32) -> Self {
        Self { x: AtomicU32::new(x.to_bits()), y: AtomicU32::new(y.to_bits()), z: AtomicU32::new(z.to_bits()) }
    }
}

#[repr(C)]
struct Player {
    health: AtomicI32,       // +0x0
    armor: AtomicI32,        // +0x4
    speed: AtomicU32,        // +0x8 (f32 bits)
    name: [u8; 16],          // +0xC
    pos: Vec3,               // +0x1C
    items: [AtomicU16; 4],   // +0x28
    next: AtomicPtr<Player>, // +0x30 (size: x64 0x38, x86 0x34)
}

#[repr(C)]
struct World {
    pad: [u64; 3],       // +0x00
    player: *mut Player, // +0x18
}

/// Static root of the pointer chain: [[WORLD]+0x18]+0x0 == player.health
static WORLD: AtomicPtr<World> = AtomicPtr::new(std::ptr::null_mut());

fn new_player(health: i32, armor: i32, speed: f32, name: &[u8], pos: Vec3, items: [u16; 4]) -> *mut Player {
    let mut n = [0u8; 16];
    n[..name.len()].copy_from_slice(name);
    Box::into_raw(Box::new(Player {
        health: AtomicI32::new(health),
        armor: AtomicI32::new(armor),
        speed: AtomicU32::new(speed.to_bits()),
        name: n,
        pos,
        items: items.map(AtomicU16::new),
        next: AtomicPtr::new(std::ptr::null_mut()),
    }))
}

// Real code for disassembly / xrefs / patch / hook / debugger tests. Relaxed atomics compile to
// plain loads and stores, so the writes happen inside these functions.

#[inline(never)]
fn take_damage(p: &Player, amount: i32) -> i32 {
    let h = p.health.load(Relaxed).wrapping_sub(amount);
    p.health.store(h, Relaxed);
    h
}

#[inline(never)]
fn heal(p: &Player, amount: i32) -> i32 {
    let h = p.health.load(Relaxed).wrapping_add(amount);
    p.health.store(h, Relaxed);
    h
}

#[inline(never)]
fn tick() -> i32 {
    let h = HEALTH.load(Relaxed).wrapping_sub(1);
    HEALTH.store(h, Relaxed);
    h
}

fn addr<T: ?Sized>(p: *const T) -> String {
    format!("0x{:X}", p as *const u8 as usize)
}

fn dump(world: *mut World, player: *mut Player) -> String {
    let p = unsafe { &*player };
    format!(
        concat!(
            "{{\"pid\":{},\"bits\":{},",
            "\"health\":\"{}\",\"gold\":\"{}\",\"speed\":\"{}\",\"precision\":\"{}\",",
            "\"name\":\"{}\",\"wname\":\"{}\",\"signature\":\"{}\",",
            "\"world_root\":\"{}\",\"world\":\"{}\",\"player\":\"{}\",",
            "\"player_health\":\"{}\",\"player_armor\":\"{}\",\"player_speed\":\"{}\",\"player_name\":\"{}\",",
            "\"player_pos\":\"{}\",\"player_items\":\"{}\",\"player_next\":\"{}\",\"sidekick\":\"{}\",",
            "\"patch\":\"{}\",",
            "\"fn_take_damage\":\"{}\",\"fn_heal\":\"{}\",\"fn_tick\":\"{}\"}}"
        ),
        std::process::id(),
        usize::BITS,
        addr(&HEALTH),
        addr(&GOLD),
        addr(&SPEED),
        addr(&PRECISION),
        addr(&NAME),
        addr(&WNAME),
        addr(&SIGNATURE),
        addr(&WORLD),
        addr(world),
        addr(player),
        addr(&p.health),
        addr(&p.armor),
        addr(&p.speed),
        addr(&p.name),
        addr(&p.pos),
        addr(&p.items),
        addr(&p.next),
        addr(p.next.load(SeqCst)),
        addr(&raw const PATCH),
        addr(take_damage as *const ()),
        addr(heal as *const ()),
        addr(tick as *const ()),
    )
}

fn main() {
    let player = new_player(250, 75, 2.25, b"Hero", Vec3::new(1.0, 2.0, 3.0), [10, 20, 30, 40]);
    let sidekick = new_player(60, 5, 1.0, b"Sidekick", Vec3::new(-1.0, 0.5, 0.0), [1, 2, 3, 4]);
    unsafe { (*player).next.store(sidekick, SeqCst) };
    let world = Box::into_raw(Box::new(World { pad: [0x1111, 0x2222, 0x3333], player }));
    WORLD.store(world, SeqCst);
    // Keep read-only statics referenced so the linker keeps them.
    std::hint::black_box((&NAME, &WNAME, &SIGNATURE));
    fill_patch();
    std::hint::black_box(&raw const PATCH);

    let p = unsafe { &*player };
    let out = std::io::stdout();
    let mut out = out.lock();
    writeln!(out, "{}", dump(world, player)).unwrap();
    out.flush().unwrap();

    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let parts: Vec<&str> = line.split_whitespace().collect();
        let reply = match parts.as_slice() {
            ["quit"] | ["exit"] => break,
            ["dump"] => dump(world, player),
            ["hit", n] => n.parse().map(|n| take_damage(p, n).to_string()).unwrap_or_else(|e| format!("err {e}")),
            ["heal", n] => n.parse().map(|n| heal(p, n).to_string()).unwrap_or_else(|e| format!("err {e}")),
            ["tick"] => tick().to_string(),
            // Allocate and fill <MB> megabytes of pseudo-random data (for scan benchmarks); prints the address.
            ["alloc", mb] => match mb.parse::<usize>() {
                Ok(mb) => {
                    let mut buf = vec![0u8; mb << 20];
                    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
                    for chunk in buf.chunks_exact_mut(8) {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        chunk.copy_from_slice(&x.to_le_bytes());
                    }
                    addr(Box::leak(buf.into_boxed_slice()).as_ptr())
                }
                Err(e) => format!("err {e}"),
            },
            ["get", f] => match *f {
                "health" => HEALTH.load(SeqCst).to_string(),
                "gold" => GOLD.load(SeqCst).to_string(),
                "speed" => f32::from_bits(SPEED.load(SeqCst)).to_string(),
                "precision" => f64::from_bits(PRECISION.load(SeqCst)).to_string(),
                "player_health" => p.health.load(SeqCst).to_string(),
                "player_armor" => p.armor.load(SeqCst).to_string(),
                "pos_x" => f32::from_bits(p.pos.x.load(SeqCst)).to_string(),
                "pos_z" => f32::from_bits(p.pos.z.load(SeqCst)).to_string(),
                "item2" => p.items[2].load(SeqCst).to_string(),
                "player_name" => {
                    let name = unsafe { std::ptr::read_volatile(&p.name) };
                    String::from_utf8_lossy(&name).trim_end_matches('\0').to_string()
                }
                "sidekick_health" => unsafe { (*p.next.load(SeqCst)).health.load(SeqCst) }.to_string(),
                _ => "err unknown field".into(),
            },
            ["set", f, v] => {
                let r: Result<(), String> = (|| {
                    match *f {
                        "health" => HEALTH.store(v.parse().map_err(|e| format!("{e}"))?, SeqCst),
                        "gold" => GOLD.store(v.parse().map_err(|e| format!("{e}"))?, SeqCst),
                        "speed" => SPEED.store(v.parse::<f32>().map_err(|e| format!("{e}"))?.to_bits(), SeqCst),
                        "precision" => PRECISION.store(v.parse::<f64>().map_err(|e| format!("{e}"))?.to_bits(), SeqCst),
                        "player_health" => p.health.store(v.parse().map_err(|e| format!("{e}"))?, SeqCst),
                        "player_armor" => p.armor.store(v.parse().map_err(|e| format!("{e}"))?, SeqCst),
                        _ => return Err("unknown field".into()),
                    }
                    Ok(())
                })();
                match r {
                    Ok(()) => "ok".into(),
                    Err(e) => format!("err {e}"),
                }
            }
            _ => "err unknown command".into(),
        };
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
}
