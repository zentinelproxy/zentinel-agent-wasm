# syntax=docker/dockerfile:1.4

# Zentinel WASM Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-wasm-agent /zentinel-wasm-agent

LABEL org.opencontainers.image.title="Zentinel WASM Agent" \
      org.opencontainers.image.description="Zentinel WASM Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-wasm"

ENV RUST_LOG=info,zentinel_wasm_agent=debug \
    SOCKET_PATH=/var/run/zentinel/wasm.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-wasm-agent"]
