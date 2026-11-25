//! Times building the per-module code index (pdata + call-target sweep) for a few large modules of
//! a running process: `cargo run --release --example code_index_bench -- <pid>`
fn main() {
    let pid: u32 = std::env::args().nth(1).expect("pid").parse().expect("pid");
    let p = memory_mcp::platform::open_process(pid).expect("open");
    let mut modules = p.modules().expect("modules");
    modules.sort_by_key(|m| std::cmp::Reverse(m.size));
    for m in modules.iter().take(4) {
        let t = std::time::Instant::now();
        match memory_mcp::disasm::functions::build_module_code(p.as_ref(), m) {
            Ok(mc) => println!(
                "{:<24} {:>6} KiB code  {:>6} pdata  {:>6} call targets  {:>6} starts  {:>5} ms",
                m.name,
                mc.exec_ranges.iter().map(|(s, e)| e - s).sum::<u64>() / 1024,
                mc.pdata.len(),
                mc.call_targets,
                mc.starts.len(),
                t.elapsed().as_millis()
            ),
            Err(e) => println!("{:<24} error: {e}", m.name),
        }
    }
}
