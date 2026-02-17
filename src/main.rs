//! Zentinel WebAssembly Agent CLI
//!
//! Command-line interface for the WebAssembly agent.
//! Supports both gRPC and UDS transports for v2 protocol.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use zentinel_agent_protocol::v2::GrpcAgentServerV2;
use zentinel_agent_wasm::WasmAgent;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-wasm-agent")]
#[command(about = "WebAssembly agent for Zentinel reverse proxy")]
struct Args {
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

    /// gRPC address to listen on (e.g., "0.0.0.0:50051").
    /// Defaults to "0.0.0.0:50051" if not specified.
    #[arg(long, env = "WASM_GRPC_ADDRESS")]
    grpc_address: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Zentinel WebAssembly Agent v2");

    // Create agent
    let agent = WasmAgent::new(&args.module, args.pool_size, args.fail_open)?;

    info!(
        module = ?args.module,
        pool_size = args.pool_size,
        fail_open = args.fail_open,
        "Agent configured"
    );

    // Determine gRPC address (use provided or default)
    let grpc_addr = args.grpc_address.unwrap_or_else(|| "0.0.0.0:50051".to_string());

    info!(
        grpc_address = %grpc_addr,
        "Starting gRPC v2 agent server"
    );

    let addr = grpc_addr
        .parse()
        .context("Invalid gRPC address format (expected host:port)")?;

    let server = GrpcAgentServerV2::new("zentinel-wasm-agent", Box::new(agent));

    info!("WebAssembly agent ready and listening on gRPC");

    server
        .run(addr)
        .await
        .context("Failed to run WebAssembly agent gRPC server")?;

    Ok(())
}
