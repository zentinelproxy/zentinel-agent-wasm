<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">WebAssembly agent</h3>

<p align="center">Runs your own WebAssembly module on request and response headers to allow, block, redirect or rewrite headers.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-wasm/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-wasm/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/wasm/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For request logic that no existing agent covers, write it in any language that
compiles to WebAssembly and let this agent run it under
[wasmtime](https://wasmtime.dev/). The module receives the request or response
headers as JSON and returns a decision as JSON. If the module fails, the agent
answers `500` (or allows the request with `--fail-open`).

## Quick start

```bash
zentinel bundle install wasm

# Build the example module (blocks /admin without Authorization, simple SQLi/XSS/traversal checks,
# adds security headers to responses)
git clone https://github.com/zentinelproxy/zentinel-agent-wasm
cd zentinel-agent-wasm/examples/wasm-module
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release

zentinel-wasm-agent \
  --socket /tmp/zentinel-wasm.sock \
  --module target/wasm32-unknown-unknown/release/example_wasm_module.wasm
```

Then point Zentinel at it:

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

agents {
    agent "wasm" type="custom" {
        unix-socket "/tmp/zentinel-wasm.sock"
        events "request_headers" "response_headers"
        timeout-ms 200
        failure-mode "closed"
    }
}

filters {
    filter "wasm" {
        type "agent"
        agent "wasm"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
        filters "wasm"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

`failure-mode "closed"` on the filter rejects requests while the agent is
unreachable; use `"open"` to forward them unprocessed instead.

```bash
curl -i http://127.0.0.1:8080/hello   # 200, with X-Frame-Options: DENY
curl -i http://127.0.0.1:8080/admin   # 401
```

## Install

### Bundle (recommended)

```bash
zentinel bundle install wasm
```

Installs the release binary for your platform. See the
[bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

### Cargo

The crate is not on crates.io; install from the repository:

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-wasm
```

This installs the `zentinel-wasm-agent` binary.

### Release binaries

Each [release](https://github.com/zentinelproxy/zentinel-agent-wasm/releases)
ships `linux-x86_64`, `linux-aarch64` and `darwin-aarch64`:

```bash
VERSION=0.3.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-wasm-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-wasm/releases/download/v${VERSION}/zentinel-wasm-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-wasm-agent.tar.gz
sudo install -m 0755 zentinel-wasm-agent /usr/local/bin/
```

### From source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-wasm
cd zentinel-agent-wasm
cargo build --release
```

## Configuration

The agent is configured with command-line flags or environment variables. A
`config { }` block on the proxy's `agent` definition does not reach it. It
serves agent protocol v2 on a Unix socket, or on gRPC with `--grpc-address`
(up to 0.3.0 it served gRPC only, on `0.0.0.0:50051` by default).

| Option | Environment | Default | Meaning |
|---|---|---|---|
| `--module` | `WASM_MODULE` | required | Path to the `.wasm` module |
| `--socket` | `AGENT_SOCKET` | `/tmp/zentinel-wasm.sock` | Unix socket to serve agent protocol v2 on |
| `--grpc-address` | `WASM_GRPC_ADDRESS` | unset | Serve gRPC on this address (e.g. `127.0.0.1:50051`) instead of the Unix socket; the proxy then connects with `grpc "http://..."` |
| `--pool-size` | `WASM_POOL_SIZE` | `4` | Module instances kept for reuse |
| `--fail-open` | `FAIL_OPEN` | `false` | On a module error, allow the request instead of answering `500` |
| `-v`, `--verbose` | `WASM_VERBOSE` | `false` | Debug logging |

Proxy-side agent options are in the
[agents reference](https://docs.zentinelproxy.io/configuration/agents/).

## Writing a module

### ABI

The module exports its memory and these functions:

```text
alloc(size: i32) -> i32                          // allocate `size` bytes, return a pointer
dealloc(ptr: i32, size: i32)                     // free them
on_request_headers(ptr: i32, len: i32) -> i64    // optional; returns (result_ptr << 32) | result_len
on_response_headers(ptr: i32, len: i32) -> i64   // optional; returns (result_ptr << 32) | result_len
```

At least one of the two handlers must be exported. A missing handler means
allow.

### Input

`on_request_headers` receives:

```json
{
  "method": "GET",
  "uri": "/api/users?page=1",
  "client_ip": "192.168.1.100",
  "correlation_id": "abc123",
  "headers": { "user-agent": "curl/8.7.1" }
}
```

`on_response_headers` receives `status`, `correlation_id` and `headers`. A
header with several values arrives as one string joined with `, `.

### Result

```json
{
  "decision": "allow",
  "status": 403,
  "body": "Forbidden",
  "add_request_headers": { "X-Processed": "true" },
  "remove_request_headers": ["X-Debug"],
  "add_response_headers": { "X-Frame-Options": "DENY" },
  "remove_response_headers": ["Server"],
  "tags": ["processed"]
}
```

Only `decision` is required.

| `decision` | Effect |
|---|---|
| `allow` (or anything unrecognized) | Continue, applying the header changes |
| `block`, `deny` | Answer with `status` (default `403`) and `body` |
| `redirect` | Answer with `status` (default `302`) and `Location: <body>` |

`tags` become audit tags. A module error is tagged `wasm-error` (plus
`fail-open` with `--fail-open`).

### Example

[`examples/wasm-module/`](examples/wasm-module/) is a complete Rust module built
with `serde_json`; build it with
`cargo build --target wasm32-unknown-unknown --release`. Header names reach the
module as the proxy received them, which is usually lowercase, so look them up
without regard to case (the example does).

## How it works

The agent compiles the module once at startup and keeps up to `--pool-size`
instances for reuse; more are created on demand under load. An instance is
reused across requests, so module globals persist between calls. No fuel or
epoch limit is set, so a module that loops forever holds its request until the
proxy's `timeout-ms` gives up on it.

## Development

```bash
# The tests load the example module
(cd examples/wasm-module && cargo build --target wasm32-unknown-unknown --release)
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Building needs Rust 1.94.1+.

`scripts/smoke-test.sh` builds the example module and runs the release binary
behind a real Zentinel with the shared harness (`agent-smoke/smoke.py` from
[zentinelproxy/.github](https://github.com/zentinelproxy/.github)): an
ordinary request is forwarded with `X-Wasm-Processed: true`, `/admin` without
an `Authorization` header gets `401`, a scanner `User-Agent` and a
SQL-injection-looking query get `403`, and stopping the agent changes the
answer. CI runs it on every push; a release runs it on every platform before
anything is published.

```bash
AGENT_SMOKE=../.github/agent-smoke/smoke.py scripts/smoke-test.sh target/release/zentinel-wasm-agent ./zentinel
```

## Related

- [Registry page](https://registry.zentinelproxy.io/wasm/)
- [zentinel-agent-js](https://github.com/zentinelproxy/zentinel-agent-js) and [zentinel-agent-lua](https://github.com/zentinelproxy/zentinel-agent-lua): scripted agents without a compile step
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
