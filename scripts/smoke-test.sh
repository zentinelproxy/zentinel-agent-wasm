#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary> [harness args...]]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request. Extra
# arguments go to the harness (e.g. `--transport grpc`).
#
# Loads the example guest module (examples/wasm-module, built here for
# wasm32-unknown-unknown unless WASM_MODULE names a built one):
#   * the v2 handshake works and an ordinary request is forwarded (200) with
#     the X-Wasm-Processed header the module adds;
#   * /admin without an Authorization header gets 401 (with one, 200), a
#     scanner User-Agent and a SQL-injection-looking query get 403, none of
#     them reaching the upstream; /public is forwarded;
#   * with the agent stopped the ordinary request is refused.

set -euo pipefail

if [ $# -ge 2 ]; then AGENT_BIN=$1 ZENTINEL_BIN=$2; shift 2; fi
AGENT_BIN=${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
ZENTINEL_BIN=${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -z "${WASM_MODULE:-}" ]; then
    cargo build --locked --release --target wasm32-unknown-unknown \
        --manifest-path "$ROOT/examples/wasm-module/Cargo.toml"
    WASM_MODULE="$ROOT/examples/wasm-module/target/wasm32-unknown-unknown/release/example_wasm_module.wasm"
fi

python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name wasm \
    --agent-arg=--module --agent-arg "$WASM_MODULE" \
    --clean '{"name": "ordinary request", "path": "/smoke", "upstream_headers": {"X-Wasm-Processed": "true"}}' \
    --case '{"name": "/admin without credentials", "path": "/admin", "expect": 401}' \
    --case '{"name": "/admin with credentials", "path": "/admin", "headers": {"Authorization": "Bearer smoke"}, "expect": 200}' \
    --case '{"name": "scanner User-Agent", "path": "/smoke", "headers": {"User-Agent": "sqlmap/1.8"}, "expect": 403}' \
    --case '{"name": "SQL injection in the query", "path": "/search?q=1+union+select+password", "expect": 403}' \
    --case '{"name": "/public allowed", "path": "/public/index.html", "expect": 200, "upstream_headers": {"X-Wasm-Processed": "true"}}' \
    "$@"
