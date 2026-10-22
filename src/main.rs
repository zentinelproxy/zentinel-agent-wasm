//! Zentinel WebAssembly Agent CLI
//!
//! Command-line interface for the WebAssembly agent.
//! Serves agent protocol v2 over a Unix socket (`--socket`, the default) or
//! gRPC (`--grpc-address`).

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use zentinel_agent_wasm::WasmAgent;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-wasm-agent")]
#[command(about = "WebAssembly agent for Zentinel reverse proxy")]
#[command(version)]
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

    /// Unix socket to listen on (agent protocol v2 over UDS). Used unless
    /// `--grpc-address` is given.
    #[arg(long, default_value = "/tmp/zentinel-wasm.sock", env = "AGENT_SOCKET")]
    socket: PathBuf,

    /// gRPC address to listen on (e.g. "127.0.0.1:50051"). When given, the
    /// agent serves agent protocol v2 over gRPC instead of the Unix socket.
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

    if let Some(grpc_addr) = args.grpc_address {
        let addr = grpc_addr
            .parse()
            .context("Invalid gRPC address format (expected host:port)")?;
        info!(grpc_address = %grpc_addr, "Listening on gRPC (agent protocol v2)");
        GrpcAgentServerV2::new("zentinel-wasm-agent", Box::new(agent))
            .run(addr)
            .await
            .context("Failed to run WebAssembly agent gRPC server")?;
    } else {
        info!(socket = %args.socket.display(), "Listening on Unix socket (agent protocol v2)");
        UdsAgentServerV2::new("zentinel-wasm-agent", args.socket, Box::new(agent))
            .run()
            .await
            .context("Failed to run WebAssembly agent UDS server")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names_the_binary() {
        let err = Args::try_parse_from(["x", "--version"]).unwrap_err();
        assert_eq!(
            err.to_string().trim(),
            format!("zentinel-wasm-agent {}", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn defaults_to_the_unix_socket() {
        let args = Args::try_parse_from(["x", "--module", "m.wasm"]).unwrap();
        assert!(args.grpc_address.is_none());
        assert_eq!(args.socket, PathBuf::from("/tmp/zentinel-wasm.sock"));
    }
}
