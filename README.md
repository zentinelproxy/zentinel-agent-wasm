# sentinel-agent-wasm

WebAssembly agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Execute custom Wasm modules for request/response processing.

## Features

- Execute WebAssembly modules for request/response lifecycle events
- Fast, secure wasmtime runtime with instance pooling
- Language-agnostic: write modules in Rust, Go, C, AssemblyScript, or any language that compiles to Wasm
- JSON-based data exchange between host and module
- Header manipulation (add/remove request and response headers)
- Audit tags for logging and analytics
- Fail-open mode for graceful error handling

## Installation

### From crates.io

```bash
cargo install sentinel-agent-wasm
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-wasm
cd sentinel-agent-wasm
cargo build --release
```

## Usage

```bash
sentinel-wasm-agent --socket /var/run/sentinel/wasm.sock \
  --module /etc/sentinel/modules/security.wasm
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-wasm.sock` |
| `--module` | `WASM_MODULE` | Wasm module file (.wasm) | (required) |
| `--pool-size` | `WASM_POOL_SIZE` | Instance pool size | `4` |
| `--verbose` | `WASM_VERBOSE` | Enable debug logging | `false` |
| `--fail-open` | `FAIL_OPEN` | Allow requests on module errors | `false` |

## Writing Wasm Modules

### Required ABI

Modules must export the following functions:

```text
// Memory allocation (required)
alloc(size: i32) -> i32          // Allocate `size` bytes, return pointer
dealloc(ptr: i32, size: i32)     // Free memory at `ptr`

// Request/Response handlers (at least one required)
on_request_headers(ptr: i32, len: i32) -> i64   // Returns (result_ptr << 32) | result_len
on_response_headers(ptr: i32, len: i32) -> i64  // Returns (result_ptr << 32) | result_len
```

### Data Exchange

The host passes JSON data to handlers and expects JSON back.

#### Request Object (on_request_headers)

```json
{
    "method": "GET",
    "uri": "/api/users?page=1",
    "client_ip": "192.168.1.100",
    "correlation_id": "abc123",
    "headers": {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0..."
    }
}
```

#### Response Object (on_response_headers)

```json
{
    "status": 200,
    "correlation_id": "abc123",
    "headers": {
        "Content-Type": "application/json",
        "X-Custom": "value"
    }
}
```

#### Result Object (return value)

```json
{
    "decision": "allow",
    "status": 403,
    "body": "Forbidden",
    "add_request_headers": {"X-Processed": "true"},
    "remove_request_headers": ["X-Debug"],
    "add_response_headers": {"X-Frame-Options": "DENY"},
    "remove_response_headers": ["Server"],
    "tags": ["processed", "logged"]
}
```

### Decision Values

| Decision | Description |
|----------|-------------|
| `allow` | Allow the request/response to proceed |
| `block` | Block with given status (default: 403) and body |
| `deny` | Same as block |
| `redirect` | Redirect to URL in `body` field (default: 302) |

## Example: Rust Module

See `examples/wasm-module/` for a complete example. Key parts:

```rust
use serde::{Deserialize, Serialize};
use std::alloc::{alloc as heap_alloc, dealloc as heap_dealloc, Layout};

#[derive(Deserialize)]
struct Request {
    method: String,
    uri: String,
    client_ip: String,
    headers: std::collections::HashMap<String, String>,
}

#[derive(Serialize, Default)]
struct Result {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { heap_alloc(layout) as i32 }
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { heap_dealloc(ptr as *mut u8, layout) }
}

#[no_mangle]
pub extern "C" fn on_request_headers(ptr: i32, len: i32) -> i64 {
    // Read input JSON from memory
    let input = unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);
        std::str::from_utf8(slice).unwrap()
    };

    // Parse request
    let request: Request = serde_json::from_str(input).unwrap();

    // Apply security rules
    let result = if request.uri.contains("/admin") {
        Result {
            decision: "block".to_string(),
            status: Some(403),
            body: Some("Forbidden".to_string()),
        }
    } else {
        Result {
            decision: "allow".to_string(),
            ..Default::default()
        }
    };

    // Serialize and return result
    let output = serde_json::to_string(&result).unwrap();
    let bytes = output.as_bytes();
    let len = bytes.len() as i32;
    let ptr = alloc(len);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
    }
    ((ptr as i64) << 32) | (len as i64)
}
```

Build with:
```bash
cargo build --target wasm32-unknown-unknown --release
```

## Building the Example Module

```bash
cd examples/wasm-module
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
```

The module will be at `examples/wasm-module/target/wasm32-unknown-unknown/release/example_wasm_module.wasm`.

## Instance Pooling

The agent maintains a pool of pre-initialized Wasm instances for performance. Configure with `--pool-size`:

- **Pool size 1**: Minimum memory, sequential processing
- **Pool size 4** (default): Good balance for most workloads
- **Pool size 8+**: High-concurrency scenarios

## Sentinel Proxy Configuration

```kdl
agents {
    agent "wasm" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/wasm.sock"
        }
        events ["request_headers", "response_headers"]
        timeout-ms 50
        failure-mode "open"
    }
}
```

## Error Handling

When `--fail-open` is enabled, module errors will:
- Log the error
- Allow the request to proceed
- Add `wasm-error` and `fail-open` tags to audit metadata

When `--fail-open` is disabled (default), module errors will:
- Log the error
- Block the request with 500 status
- Add `wasm-error` tag to audit metadata

## Comparison with Other Agents

| Feature | sentinel-agent-wasm | sentinel-agent-js | sentinel-agent-lua |
|---------|--------------------|--------------------|-------------------|
| Language | Any (Rust, Go, C, etc.) | JavaScript | Lua |
| Runtime | wasmtime | QuickJS | mlua |
| Performance | Fastest | Fast | Fast |
| Sandboxing | Strong (Wasm isolation) | Basic | Comprehensive |
| Ecosystem | Wasm-compatible libraries | Limited | Lua libraries |
| Complexity | Higher (compilation required) | Lower | Lower |

Use `sentinel-agent-wasm` for:
- Maximum performance requirements
- Existing Rust/Go/C code that needs minimal porting
- Strong isolation between modules
- Memory-safe execution

## Development

```bash
# Run tests (requires example module)
cd examples/wasm-module && cargo build --target wasm32-unknown-unknown --release && cd ../..
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --module ./examples/wasm-module/target/wasm32-unknown-unknown/release/example_wasm_module.wasm --verbose
```

## License

MIT OR Apache-2.0
