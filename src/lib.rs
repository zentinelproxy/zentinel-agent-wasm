//! Sentinel WebAssembly Agent Library
//!
//! A WebAssembly agent for Sentinel reverse proxy that executes Wasm modules
//! for request/response processing. Modules can be written in any language
//! that compiles to WebAssembly (Rust, Go, C, AssemblyScript, etc.).
//!
//! # Wasm Module ABI
//!
//! Modules must export the following functions:
//!
//! ```text
//! // Memory allocation (required)
//! alloc(size: i32) -> i32          // Allocate `size` bytes, return pointer
//! dealloc(ptr: i32, size: i32)     // Free memory at `ptr`
//!
//! // Request/Response handlers (at least one required)
//! on_request_headers(ptr: i32, len: i32) -> i64   // Returns (result_ptr << 32) | result_len
//! on_response_headers(ptr: i32, len: i32) -> i64  // Returns (result_ptr << 32) | result_len
//! ```
//!
//! The host passes JSON data to the module and expects JSON back.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use wasmtime::*;

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, HeaderOp, RequestHeadersEvent,
    ResponseHeadersEvent,
};

/// Result from Wasm module execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WasmResult {
    /// Decision: "allow", "block", "deny", or "redirect"
    pub decision: String,
    /// HTTP status code for block/redirect
    pub status: Option<u16>,
    /// Response body for block, or URL for redirect
    pub body: Option<String>,
    /// Request headers to add
    pub add_request_headers: Option<HashMap<String, String>>,
    /// Request headers to remove
    pub remove_request_headers: Option<Vec<String>>,
    /// Response headers to add
    pub add_response_headers: Option<HashMap<String, String>>,
    /// Response headers to remove
    pub remove_response_headers: Option<Vec<String>>,
    /// Audit tags
    pub tags: Option<Vec<String>>,
}

/// Request data passed to Wasm module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRequest {
    pub method: String,
    pub uri: String,
    pub client_ip: String,
    pub correlation_id: String,
    pub headers: HashMap<String, String>,
}

/// Response data passed to Wasm module
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmResponse {
    pub status: u16,
    pub correlation_id: String,
    pub headers: HashMap<String, String>,
}

/// Wasm module instance with exported functions
struct WasmInstance {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<i32, i32>,
    dealloc: TypedFunc<(i32, i32), ()>,
    on_request_headers: Option<TypedFunc<(i32, i32), i64>>,
    on_response_headers: Option<TypedFunc<(i32, i32), i64>>,
}

/// WebAssembly agent
pub struct WasmAgent {
    engine: Engine,
    module: Module,
    instance_pool: Arc<Mutex<Vec<WasmInstance>>>,
    pool_size: usize,
    fail_open: bool,
}

// WasmAgent is Send + Sync because we protect instance access with Mutex
unsafe impl Send for WasmAgent {}
unsafe impl Sync for WasmAgent {}

impl WasmAgent {
    /// Create a new Wasm agent from a module file
    pub fn new<P: AsRef<Path>>(module_path: P, pool_size: usize, fail_open: bool) -> Result<Self> {
        let module_bytes = std::fs::read(module_path.as_ref())
            .with_context(|| format!("Failed to read Wasm module: {:?}", module_path.as_ref()))?;

        Self::from_bytes(&module_bytes, pool_size, fail_open)
    }

    /// Create a new Wasm agent from module bytes
    pub fn from_bytes(module_bytes: &[u8], pool_size: usize, fail_open: bool) -> Result<Self> {
        let mut config = Config::new();
        config.wasm_multi_memory(true);
        config.wasm_bulk_memory(true);

        let engine = Engine::new(&config).context("Failed to create Wasm engine")?;
        let module = Module::new(&engine, module_bytes).context("Failed to compile Wasm module")?;

        info!("Wasm module compiled successfully");

        let agent = Self {
            engine,
            module,
            instance_pool: Arc::new(Mutex::new(Vec::with_capacity(pool_size))),
            pool_size,
            fail_open,
        };

        Ok(agent)
    }

    /// Create a new Wasm instance
    fn create_instance(&self) -> Result<WasmInstance> {
        let mut store = Store::new(&self.engine, ());
        let instance = Instance::new(&mut store, &self.module, &[])
            .context("Failed to instantiate Wasm module")?;

        // Get memory export
        let memory = instance
            .get_memory(&mut store, "memory")
            .context("Wasm module must export 'memory'")?;

        // Get required exports
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .context("Wasm module must export 'alloc(i32) -> i32'")?;

        let dealloc = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "dealloc")
            .context("Wasm module must export 'dealloc(i32, i32)'")?;

        // Get optional handler exports
        let on_request_headers = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "on_request_headers")
            .ok();

        let on_response_headers = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "on_response_headers")
            .ok();

        if on_request_headers.is_none() && on_response_headers.is_none() {
            anyhow::bail!(
                "Wasm module must export at least one of: on_request_headers, on_response_headers"
            );
        }

        debug!("Created new Wasm instance");

        Ok(WasmInstance {
            store,
            memory,
            alloc,
            dealloc,
            on_request_headers,
            on_response_headers,
        })
    }

    /// Get or create an instance from the pool
    async fn acquire_instance(&self) -> Result<WasmInstance> {
        let mut pool = self.instance_pool.lock().await;
        if let Some(instance) = pool.pop() {
            Ok(instance)
        } else {
            drop(pool); // Release lock while creating instance
            self.create_instance()
        }
    }

    /// Return an instance to the pool
    async fn release_instance(&self, instance: WasmInstance) {
        let mut pool = self.instance_pool.lock().await;
        if pool.len() < self.pool_size {
            pool.push(instance);
        }
        // Otherwise, instance is dropped
    }

    /// Check if request handler exists
    fn has_request_handler(instance: &WasmInstance) -> bool {
        instance.on_request_headers.is_some()
    }

    /// Check if response handler exists
    fn has_response_handler(instance: &WasmInstance) -> bool {
        instance.on_response_headers.is_some()
    }

    /// Call request headers handler with JSON input and get JSON output
    fn call_request_handler(instance: &mut WasmInstance, input_json: &str) -> Result<String> {
        let handler = instance
            .on_request_headers
            .clone()
            .expect("on_request_headers should exist");
        Self::call_wasm_handler_impl(instance, handler, input_json)
    }

    /// Call response headers handler with JSON input and get JSON output
    fn call_response_handler(instance: &mut WasmInstance, input_json: &str) -> Result<String> {
        let handler = instance
            .on_response_headers
            .clone()
            .expect("on_response_headers should exist");
        Self::call_wasm_handler_impl(instance, handler, input_json)
    }

    /// Internal helper to call a Wasm handler
    fn call_wasm_handler_impl(
        instance: &mut WasmInstance,
        handler: TypedFunc<(i32, i32), i64>,
        input_json: &str,
    ) -> Result<String> {
        let input_bytes = input_json.as_bytes();
        let input_len = input_bytes.len() as i32;

        // Allocate memory in Wasm for input
        let input_ptr = instance
            .alloc
            .call(&mut instance.store, input_len)
            .context("Failed to allocate input memory")?;

        // Write input to Wasm memory
        instance
            .memory
            .write(&mut instance.store, input_ptr as usize, input_bytes)
            .context("Failed to write input to Wasm memory")?;

        // Call the handler
        let result = handler
            .call(&mut instance.store, (input_ptr, input_len))
            .context("Wasm handler call failed")?;

        // Free input memory
        instance
            .dealloc
            .call(&mut instance.store, (input_ptr, input_len))
            .ok(); // Ignore dealloc errors

        // Extract result pointer and length from packed i64
        let result_ptr = (result >> 32) as i32;
        let result_len = (result & 0xFFFFFFFF) as i32;

        if result_ptr == 0 || result_len == 0 {
            return Ok(r#"{"decision":"allow"}"#.to_string());
        }

        // Read result from Wasm memory
        let mut result_bytes = vec![0u8; result_len as usize];
        instance
            .memory
            .read(&instance.store, result_ptr as usize, &mut result_bytes)
            .context("Failed to read result from Wasm memory")?;

        // Free result memory
        instance
            .dealloc
            .call(&mut instance.store, (result_ptr, result_len))
            .ok(); // Ignore dealloc errors

        String::from_utf8(result_bytes).context("Wasm result is not valid UTF-8")
    }

    /// Build AgentResponse from WasmResult
    pub fn build_response(result: WasmResult) -> AgentResponse {
        let decision = result.decision.to_lowercase();

        let mut response = match decision.as_str() {
            "block" | "deny" => {
                let status = result.status.unwrap_or(403);
                AgentResponse::block(status, result.body)
            }
            "redirect" => {
                let status = result.status.unwrap_or(302);
                let mut resp = AgentResponse::block(status, None);
                if let Some(url) = result.body {
                    resp = resp.add_response_header(HeaderOp::Set {
                        name: "Location".to_string(),
                        value: url,
                    });
                }
                resp
            }
            _ => AgentResponse::default_allow(),
        };

        // Add request headers
        if let Some(headers) = result.add_request_headers {
            for (name, value) in headers {
                response = response.add_request_header(HeaderOp::Set { name, value });
            }
        }

        // Remove request headers
        if let Some(headers) = result.remove_request_headers {
            for name in headers {
                response = response.add_request_header(HeaderOp::Remove { name });
            }
        }

        // Add response headers
        if let Some(headers) = result.add_response_headers {
            for (name, value) in headers {
                response = response.add_response_header(HeaderOp::Set { name, value });
            }
        }

        // Remove response headers
        if let Some(headers) = result.remove_response_headers {
            for name in headers {
                response = response.add_response_header(HeaderOp::Remove { name });
            }
        }

        // Add audit tags
        if let Some(tags) = result.tags {
            response = response.with_audit(AuditMetadata {
                tags,
                ..Default::default()
            });
        }

        response
    }

    /// Handle execution error
    fn handle_error(&self, error: anyhow::Error, correlation_id: &str) -> AgentResponse {
        error!(
            correlation_id = correlation_id,
            error = %error,
            "Wasm execution failed"
        );

        if self.fail_open {
            AgentResponse::default_allow().with_audit(AuditMetadata {
                tags: vec!["wasm-error".to_string(), "fail-open".to_string()],
                reason_codes: vec![error.to_string()],
                ..Default::default()
            })
        } else {
            AgentResponse::block(500, Some("Wasm Error".to_string())).with_audit(AuditMetadata {
                tags: vec!["wasm-error".to_string()],
                reason_codes: vec![error.to_string()],
                ..Default::default()
            })
        }
    }
}

#[async_trait]
impl AgentHandler for WasmAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let correlation_id = event.metadata.correlation_id.clone();

        // Acquire instance from pool
        let mut instance = match self.acquire_instance().await {
            Ok(inst) => inst,
            Err(e) => return self.handle_error(e, &correlation_id),
        };

        // Build request object
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, values) in &event.headers {
            headers.insert(name.clone(), values.join(", "));
        }

        let request = WasmRequest {
            method: event.method.clone(),
            uri: event.uri.clone(),
            client_ip: event.metadata.client_ip.clone(),
            correlation_id: correlation_id.clone(),
            headers,
        };

        let input_json = match serde_json::to_string(&request) {
            Ok(j) => j,
            Err(e) => {
                self.release_instance(instance).await;
                return self.handle_error(e.into(), &correlation_id);
            }
        };

        // Check if handler exists
        if !Self::has_request_handler(&instance) {
            self.release_instance(instance).await;
            return AgentResponse::default_allow();
        }

        // Call Wasm handler
        let result = Self::call_request_handler(&mut instance, &input_json);

        // Release instance back to pool
        self.release_instance(instance).await;

        match result {
            Ok(output_json) => {
                debug!(
                    correlation_id = correlation_id,
                    output = %output_json,
                    "Wasm handler returned"
                );

                match serde_json::from_str::<WasmResult>(&output_json) {
                    Ok(wasm_result) => Self::build_response(wasm_result),
                    Err(e) => {
                        warn!(
                            correlation_id = correlation_id,
                            error = %e,
                            output = %output_json,
                            "Failed to parse Wasm result"
                        );
                        self.handle_error(e.into(), &correlation_id)
                    }
                }
            }
            Err(e) => self.handle_error(e, &correlation_id),
        }
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let correlation_id = event.correlation_id.clone();

        // Acquire instance from pool
        let mut instance = match self.acquire_instance().await {
            Ok(inst) => inst,
            Err(e) => return self.handle_error(e, &correlation_id),
        };

        // Build response object
        let mut headers: HashMap<String, String> = HashMap::new();
        for (name, values) in &event.headers {
            headers.insert(name.clone(), values.join(", "));
        }

        let response = WasmResponse {
            status: event.status,
            correlation_id: correlation_id.clone(),
            headers,
        };

        let input_json = match serde_json::to_string(&response) {
            Ok(j) => j,
            Err(e) => {
                self.release_instance(instance).await;
                return self.handle_error(e.into(), &correlation_id);
            }
        };

        // Check if handler exists
        if !Self::has_response_handler(&instance) {
            self.release_instance(instance).await;
            return AgentResponse::default_allow();
        }

        // Call Wasm handler
        let result = Self::call_response_handler(&mut instance, &input_json);

        // Release instance back to pool
        self.release_instance(instance).await;

        match result {
            Ok(output_json) => {
                debug!(
                    correlation_id = correlation_id,
                    output = %output_json,
                    "Wasm handler returned"
                );

                match serde_json::from_str::<WasmResult>(&output_json) {
                    Ok(wasm_result) => Self::build_response(wasm_result),
                    Err(e) => {
                        warn!(
                            correlation_id = correlation_id,
                            error = %e,
                            output = %output_json,
                            "Failed to parse Wasm result"
                        );
                        self.handle_error(e.into(), &correlation_id)
                    }
                }
            }
            Err(e) => self.handle_error(e, &correlation_id),
        }
    }
}
