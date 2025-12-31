//! Sentinel WebAssembly Agent CLI
//!
//! Command-line interface for the WebAssembly agent.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use sentinel_agent_protocol::AgentServer;
use sentinel_agent_wasm::WasmAgent;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "sentinel-wasm-agent")]
#[command(about = "WebAssembly agent for Sentinel reverse proxy")]
struct Args {
    /// Path to Unix socket
    #[arg(long, default_value = "/tmp/sentinel-wasm.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// Path to WebAssembly module (.wasm file)
    #[arg(long, env = "WASM_MODULE")]
    module: PathBuf,

    /// Instance pool size (number of pre-initialized Wasm instances)
    #[arg(long, default_value = "4", env = "WASM_POOL_SIZE")]
    pool_size: usize,

    /// Enable verbose logging
    #[arg(short, long, env = "WASM_VERBOSE")]
    verbose: bool,

    /// Fail open on Wasm errors (allow requests instead of blocking)
    #[arg(long, env = "FAIL_OPEN")]
    fail_open: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},sentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Sentinel WebAssembly Agent");

    // Create agent
    let agent = WasmAgent::new(&args.module, args.pool_size, args.fail_open)?;

    info!(
        module = ?args.module,
        pool_size = args.pool_size,
        fail_open = args.fail_open,
        "Agent configured"
    );

    // Start agent server
    info!(socket = ?args.socket, "Starting agent server");
    let server = AgentServer::new("sentinel-wasm-agent", args.socket, Box::new(agent));
    server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(())
}
