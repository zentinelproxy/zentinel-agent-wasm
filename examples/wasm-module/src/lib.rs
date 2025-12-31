//! Example Wasm module for Sentinel
//!
//! This module demonstrates how to write a Wasm module that works with
//! the sentinel-agent-wasm runtime.
//!
//! Build with:
//! ```bash
//! cargo build --target wasm32-unknown-unknown --release
//! ```

use serde::{Deserialize, Serialize};
use std::alloc::{alloc as heap_alloc, dealloc as heap_dealloc, Layout};
use std::collections::HashMap;

/// Request data from the host
#[derive(Debug, Deserialize)]
struct Request {
    method: String,
    uri: String,
    client_ip: String,
    correlation_id: String,
    headers: HashMap<String, String>,
}

/// Response data from the host
#[derive(Debug, Deserialize)]
struct Response {
    status: u16,
    correlation_id: String,
    headers: HashMap<String, String>,
}

/// Result to return to the host
#[derive(Debug, Serialize, Default)]
struct Result {
    decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_request_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_request_headers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    add_response_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remove_response_headers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<Vec<String>>,
}

/// Allocate memory for the host to write data
#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    if size <= 0 {
        return 0;
    }
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { heap_alloc(layout) as i32 }
}

/// Free memory allocated by this module
#[no_mangle]
pub extern "C" fn dealloc(ptr: i32, size: i32) {
    if ptr == 0 || size <= 0 {
        return;
    }
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { heap_dealloc(ptr as *mut u8, layout) }
}

/// Process request headers
///
/// Returns (result_ptr << 32) | result_len as i64
#[no_mangle]
pub extern "C" fn on_request_headers(ptr: i32, len: i32) -> i64 {
    // Read input JSON from memory
    let input = unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    // Parse request
    let request: Request = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    // Apply security rules
    let result = process_request(&request);

    // Serialize result
    let output = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Allocate and write result
    write_result(&output)
}

/// Process response headers
///
/// Returns (result_ptr << 32) | result_len as i64
#[no_mangle]
pub extern "C" fn on_response_headers(ptr: i32, len: i32) -> i64 {
    // Read input JSON from memory
    let input = unsafe {
        let slice = std::slice::from_raw_parts(ptr as *const u8, len as usize);
        match std::str::from_utf8(slice) {
            Ok(s) => s,
            Err(_) => return 0,
        }
    };

    // Parse response
    let response: Response = match serde_json::from_str(input) {
        Ok(r) => r,
        Err(_) => return 0,
    };

    // Apply security rules
    let result = process_response(&response);

    // Serialize result
    let output = match serde_json::to_string(&result) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Allocate and write result
    write_result(&output)
}

/// Write result string to memory and return packed pointer/length
fn write_result(output: &str) -> i64 {
    let bytes = output.as_bytes();
    let len = bytes.len() as i32;
    let ptr = alloc(len);
    if ptr == 0 {
        return 0;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len());
    }

    ((ptr as i64) << 32) | (len as i64)
}

/// Process request and return decision
fn process_request(request: &Request) -> Result {
    let uri_lower = request.uri.to_lowercase();
    let mut tags = Vec::new();

    // Block admin access without auth
    if uri_lower.contains("/admin") {
        if !request.headers.contains_key("Authorization") {
            return Result {
                decision: "block".to_string(),
                status: Some(401),
                body: Some("Authentication required".to_string()),
                tags: Some(vec!["admin-blocked".to_string()]),
                ..Default::default()
            };
        }
        tags.push("admin-access".to_string());
    }

    // Block common attack patterns
    // SQL injection
    if uri_lower.contains("'") || uri_lower.contains("--") || uri_lower.contains("union") {
        return Result {
            decision: "block".to_string(),
            status: Some(403),
            body: Some("Forbidden".to_string()),
            tags: Some(vec!["sqli-detected".to_string()]),
            ..Default::default()
        };
    }

    // Path traversal
    if uri_lower.contains("..") || uri_lower.contains("%2e%2e") {
        return Result {
            decision: "block".to_string(),
            status: Some(403),
            body: Some("Forbidden".to_string()),
            tags: Some(vec!["path-traversal".to_string()]),
            ..Default::default()
        };
    }

    // XSS in query string
    if uri_lower.contains("<script") || uri_lower.contains("javascript:") {
        return Result {
            decision: "block".to_string(),
            status: Some(403),
            body: Some("Forbidden".to_string()),
            tags: Some(vec!["xss-detected".to_string()]),
            ..Default::default()
        };
    }

    // Check for scanner user agents
    if let Some(ua) = request.headers.get("User-Agent") {
        let ua_lower = ua.to_lowercase();
        if ua_lower.contains("sqlmap") || ua_lower.contains("nikto") || ua_lower.contains("nessus")
        {
            return Result {
                decision: "block".to_string(),
                status: Some(403),
                body: Some("Forbidden".to_string()),
                tags: Some(vec!["scanner-blocked".to_string()]),
                ..Default::default()
            };
        }
    }

    // Add request headers
    let mut add_headers = HashMap::new();
    add_headers.insert("X-Wasm-Processed".to_string(), "true".to_string());
    add_headers.insert("X-Client-IP".to_string(), request.client_ip.clone());

    Result {
        decision: "allow".to_string(),
        add_request_headers: Some(add_headers),
        tags: if tags.is_empty() { None } else { Some(tags) },
        ..Default::default()
    }
}

/// Process response and return decision
fn process_response(response: &Response) -> Result {
    // Add security headers
    let mut add_headers = HashMap::new();
    add_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
    add_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
    add_headers.insert(
        "X-XSS-Protection".to_string(),
        "1; mode=block".to_string(),
    );

    // Remove sensitive headers
    let remove_headers = vec![
        "Server".to_string(),
        "X-Powered-By".to_string(),
    ];

    Result {
        decision: "allow".to_string(),
        add_response_headers: Some(add_headers),
        remove_response_headers: Some(remove_headers),
        tags: Some(vec![format!("status-{}", response.status)]),
        ..Default::default()
    }
}
