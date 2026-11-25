use std::path::PathBuf;

use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use memory_mcp::server::ServerOptions;
use memory_mcp::{MemoryServer, journal};

const USAGE: &str = "memory-mcp [options]

Local MCP server (stdio) for reading, writing and scanning process memory.

  --journal <file>   append the write journal to this JSONL file
                     (default: <data dir>/memory-mcp/writes.jsonl, or $MEMORY_MCP_JOURNAL)
  --no-journal       keep the write journal in memory only (undo still works)
  --structs <file>   load/save struct templates in this JSON file
                     (default: <data dir>/memory-mcp/structs.json, or $MEMORY_MCP_STRUCTS)
  --no-structs-file  keep struct templates in memory only
  -h, --help         show this help

<data dir> is %LOCALAPPDATA% on Windows, $XDG_STATE_HOME or ~/.local/state elsewhere.";

fn data_file(env: &str, name: &str) -> Option<PathBuf> {
    std::env::var_os(env)
        .map(PathBuf::from)
        .or_else(|| journal::default_path().and_then(|p| p.parent().map(|d| d.join(name))))
}

fn options() -> anyhow::Result<ServerOptions> {
    let mut opts = ServerOptions {
        journal: data_file("MEMORY_MCP_JOURNAL", "writes.jsonl"),
        structs: data_file("MEMORY_MCP_STRUCTS", "structs.json"),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--journal" => {
                opts.journal = Some(PathBuf::from(args.next().ok_or_else(|| anyhow::anyhow!("--journal needs a path"))?));
            }
            "--no-journal" => opts.journal = None,
            "--structs" => {
                opts.structs = Some(PathBuf::from(args.next().ok_or_else(|| anyhow::anyhow!("--structs needs a path"))?));
            }
            "--no-structs-file" => opts.structs = None,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => anyhow::bail!("unknown argument '{other}'\n\n{USAGE}"),
        }
    }
    Ok(opts)
}

fn show(p: &Option<PathBuf>) -> String {
    p.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "memory only".into())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout carries the MCP protocol, so logs go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let opts = options()?;
    tracing::info!(
        "memory-mcp {} starting on stdio; write journal: {}; struct templates: {}",
        env!("CARGO_PKG_VERSION"),
        show(&opts.journal),
        show(&opts.structs)
    );
    let service = MemoryServer::with_options(opts).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
