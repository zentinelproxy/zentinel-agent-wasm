//! Integration tests for the WebAssembly agent using sentinel-agent-protocol.
//!
//! These tests spin up an actual AgentServer and connect via AgentClient
//! to verify the full protocol flow.
//!
//! Note: Tests require the example Wasm module to be built first:
//! ```bash
//! cd examples/wasm-module && cargo build --target wasm32-unknown-unknown --release
//! ```

use sentinel_agent_protocol::{
    AgentClient, AgentServer, Decision, EventType, HeaderOp, RequestHeadersEvent, RequestMetadata,
    ResponseHeadersEvent,
};
use sentinel_agent_wasm::WasmAgent;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;

/// Get path to the example Wasm module
fn example_module_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/wasm-module/target/wasm32-unknown-unknown/release/example_wasm_module.wasm")
}

/// Check if the example module exists
fn module_exists() -> bool {
    example_module_path().exists()
}

/// Helper to start a Wasm agent server and return the socket path
async fn start_test_server(fail_open: bool) -> Option<(tempfile::TempDir, std::path::PathBuf)> {
    if !module_exists() {
        return None;
    }

    let dir = tempdir().expect("Failed to create temp dir");
    let socket_path = dir.path().join("wasm-test.sock");

    let agent =
        WasmAgent::new(example_module_path(), 2, fail_open).expect("Failed to create agent");
    let server = AgentServer::new("test-wasm", socket_path.clone(), Box::new(agent));

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Some((dir, socket_path))
}

/// Create a client connected to the test server
async fn create_client(socket_path: &std::path::Path) -> AgentClient {
    AgentClient::unix_socket("test-client", socket_path, Duration::from_secs(5))
        .await
        .expect("Failed to connect to agent")
}

/// Create a basic request metadata
fn make_metadata() -> RequestMetadata {
    let id = uuid::Uuid::new_v4().to_string();
    RequestMetadata {
        correlation_id: id.clone(),
        request_id: id,
        client_ip: "192.168.1.100".to_string(),
        client_port: 54321,
        server_name: Some("test.example.com".to_string()),
        protocol: "HTTP/1.1".to_string(),
        tls_version: Some("TLSv1.3".to_string()),
        tls_cipher: None,
        route_id: Some("default".to_string()),
        upstream_id: None,
        timestamp: "2025-01-01T12:00:00Z".to_string(),
        traceparent: None,
    }
}

/// Create a request headers event
fn make_request_headers(
    method: &str,
    uri: &str,
    headers: HashMap<String, Vec<String>>,
) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: make_metadata(),
        method: method.to_string(),
        uri: uri.to_string(),
        headers,
    }
}

/// Create a response headers event
fn make_response_headers(status: u16, headers: HashMap<String, Vec<String>>) -> ResponseHeadersEvent {
    ResponseHeadersEvent {
        correlation_id: uuid::Uuid::new_v4().to_string(),
        status,
        headers,
    }
}

/// Check if decision is Block
fn is_block(decision: &Decision) -> bool {
    matches!(decision, Decision::Block { .. })
}

/// Check if decision is Allow
fn is_allow(decision: &Decision) -> bool {
    matches!(decision, Decision::Allow)
}

/// Get block status code
fn get_block_status(decision: &Decision) -> Option<u16> {
    match decision {
        Decision::Block { status, .. } => Some(*status),
        _ => None,
    }
}

// ============================================================================
// Basic Decision Tests
// ============================================================================

#[tokio::test]
async fn test_allow_clean_request() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow for clean request");

    // Should have X-Wasm-Processed header
    let has_processed = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Wasm-Processed" && value == "true",
        _ => false,
    });
    assert!(has_processed, "Expected X-Wasm-Processed header");
}

#[tokio::test]
async fn test_block_admin_without_auth() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/admin/settings", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for admin without auth");
    assert_eq!(get_block_status(&response.decision), Some(401));
}

#[tokio::test]
async fn test_allow_admin_with_auth() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        vec!["Bearer token123".to_string()],
    );

    let event = make_request_headers("GET", "/admin/settings", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow for admin with auth");
}

// ============================================================================
// SQL Injection Detection Tests
// ============================================================================

#[tokio::test]
async fn test_block_sql_injection_quote() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api/users?id=1'--", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for SQL injection");
    assert_eq!(get_block_status(&response.decision), Some(403));
}

#[tokio::test]
async fn test_block_sql_injection_union() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/api/users?id=1+union+select+*+from+users",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for UNION injection");
}

// ============================================================================
// XSS Detection Tests
// ============================================================================

#[tokio::test]
async fn test_block_xss_script_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/search?q=<script>alert(1)</script>",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for XSS script tag");
}

#[tokio::test]
async fn test_block_xss_javascript_uri() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/redirect?url=javascript:alert(1)",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for javascript: URI");
}

// ============================================================================
// Path Traversal Detection Tests
// ============================================================================

#[tokio::test]
async fn test_block_path_traversal_plain() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/files/../../../etc/passwd", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for path traversal");
}

#[tokio::test]
async fn test_block_path_traversal_encoded() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/files/%2e%2e/%2e%2e/etc/passwd",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for encoded path traversal");
}

// ============================================================================
// Scanner Detection Tests
// ============================================================================

#[tokio::test]
async fn test_block_sqlmap_scanner() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["sqlmap/1.5.0 (http://sqlmap.org)".to_string()],
    );

    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for sqlmap");
}

#[tokio::test]
async fn test_block_nikto_scanner() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["Nikto/2.1.6".to_string()]);

    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for Nikto");
}

#[tokio::test]
async fn test_block_nessus_scanner() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["Nessus SOAP".to_string()],
    );

    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision), "Expected Block for Nessus");
}

#[tokio::test]
async fn test_allow_normal_browser() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert(
        "User-Agent".to_string(),
        vec!["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string()],
    );

    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision), "Expected Allow for normal browser");
}

// ============================================================================
// Header Manipulation Tests
// ============================================================================

#[tokio::test]
async fn test_adds_wasm_processed_header() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_header = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Wasm-Processed" && value == "true",
        _ => false,
    });
    assert!(has_header, "Expected X-Wasm-Processed header");
}

#[tokio::test]
async fn test_adds_client_ip_header() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api/users", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_header = response.request_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Client-IP" && value == "192.168.1.100",
        _ => false,
    });
    assert!(has_header, "Expected X-Client-IP header");
}

// ============================================================================
// Response Headers Hook Tests
// ============================================================================

#[tokio::test]
async fn test_response_adds_security_headers() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_response_headers(200, HashMap::new());
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_allow(&response.decision));

    let has_nosniff = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Content-Type-Options" && value == "nosniff",
        _ => false,
    });
    assert!(has_nosniff, "Expected X-Content-Type-Options header");

    let has_frame_options = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => name == "X-Frame-Options" && value == "DENY",
        _ => false,
    });
    assert!(has_frame_options, "Expected X-Frame-Options header");

    let has_xss = response.response_headers.iter().any(|h| match h {
        HeaderOp::Set { name, value } => {
            name == "X-XSS-Protection" && value == "1; mode=block"
        }
        _ => false,
    });
    assert!(has_xss, "Expected X-XSS-Protection header");
}

#[tokio::test]
async fn test_response_removes_server_header() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_response_headers(200, HashMap::new());
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    let removes_server = response.response_headers.iter().any(|h| match h {
        HeaderOp::Remove { name } => name == "Server",
        _ => false,
    });
    assert!(removes_server, "Expected Server header removal");

    let removes_powered_by = response.response_headers.iter().any(|h| match h {
        HeaderOp::Remove { name } => name == "X-Powered-By",
        _ => false,
    });
    assert!(removes_powered_by, "Expected X-Powered-By header removal");
}

// ============================================================================
// Audit Tags Tests
// ============================================================================

#[tokio::test]
async fn test_response_includes_status_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_response_headers(200, HashMap::new());
    let response = client
        .send_event(EventType::ResponseHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(
        response.audit.tags.contains(&"status-200".to_string()),
        "Expected status-200 tag"
    );
}

#[tokio::test]
async fn test_admin_blocked_includes_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/admin/settings", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision));
    assert!(
        response.audit.tags.contains(&"admin-blocked".to_string()),
        "Expected admin-blocked tag"
    );
}

#[tokio::test]
async fn test_sqli_blocked_includes_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/api/users?id=1'--", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision));
    assert!(
        response.audit.tags.contains(&"sqli-detected".to_string()),
        "Expected sqli-detected tag"
    );
}

#[tokio::test]
async fn test_xss_blocked_includes_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers(
        "GET",
        "/search?q=<script>alert(1)</script>",
        HashMap::new(),
    );
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision));
    assert!(
        response.audit.tags.contains(&"xss-detected".to_string()),
        "Expected xss-detected tag"
    );
}

#[tokio::test]
async fn test_path_traversal_blocked_includes_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let event = make_request_headers("GET", "/files/../../../etc/passwd", HashMap::new());
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision));
    assert!(
        response.audit.tags.contains(&"path-traversal".to_string()),
        "Expected path-traversal tag"
    );
}

#[tokio::test]
async fn test_scanner_blocked_includes_tag() {
    let Some((_dir, socket_path)) = start_test_server(false).await else {
        eprintln!("Skipping test: example module not built");
        return;
    };
    let mut client = create_client(&socket_path).await;

    let mut headers = HashMap::new();
    headers.insert("User-Agent".to_string(), vec!["sqlmap/1.5.0".to_string()]);

    let event = make_request_headers("GET", "/api/users", headers);
    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Failed to send event");

    assert!(is_block(&response.decision));
    assert!(
        response.audit.tags.contains(&"scanner-blocked".to_string()),
        "Expected scanner-blocked tag"
    );
}
