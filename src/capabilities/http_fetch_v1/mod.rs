use anyhow::Result;
use async_trait::async_trait;
use reqwest;
use serde_json::json;
use smith_protocol::{
    AllowlistHit, CapabilitySpec, ExecutionError, ExecutionStatus, Intent, ResourceRequirements,
};
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tracing::{debug, info, warn};
use url::Url;

use crate::capability::{Capability, CapabilityResult, ExecCtx, ExecutionMetadata};

/// HttpFetchV1 capability for making HTTP requests
pub struct HttpFetchV1Capability {
    client: reqwest::Client,
}

impl HttpFetchV1Capability {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Smith-Executor/1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self { client }
    }
}

#[async_trait]
impl Capability for HttpFetchV1Capability {
    fn name(&self) -> &'static str {
        "http.fetch.v1"
    }

    fn validate(&self, intent: &Intent) -> Result<(), ExecutionError> {
        // Validate that this is a http.fetch.v1 intent
        if intent.capability != smith_protocol::Capability::HttpFetchV1 {
            return Err(ExecutionError {
                code: "CAPABILITY_MISMATCH".to_string(),
                message: format!("Expected http.fetch.v1, got {}", intent.capability),
            });
        }

        // Parse and validate parameters
        if let serde_json::Value::Object(ref map) = intent.params {
            for key in map.keys() {
                match key.as_str() {
                    "url" | "method" | "headers" | "body" | "timeout_ms" => {}
                    unexpected => {
                        return Err(ExecutionError {
                            code: "INVALID_PARAMS".to_string(),
                            message: format!("Unsupported parameter provided: {}", unexpected),
                        });
                    }
                }
            }
        }

        let params: smith_protocol::params::HttpFetchV1 =
            serde_json::from_value(intent.params.clone()).map_err(|e| ExecutionError {
                code: "INVALID_PARAMS".to_string(),
                message: format!("Failed to parse http.fetch.v1 parameters: {}", e),
            })?;

        // Validate URL
        if params.url.is_empty() {
            return Err(ExecutionError {
                code: "INVALID_URL".to_string(),
                message: "URL cannot be empty".to_string(),
            });
        }

        if params.url.len() > Self::MAX_URL_LENGTH {
            return Err(ExecutionError {
                code: "INVALID_URL".to_string(),
                message: format!(
                    "URL length exceeds maximum allowed {} characters",
                    Self::MAX_URL_LENGTH
                ),
            });
        }

        // Parse URL to validate format
        let url = Url::parse(&params.url).map_err(|e| ExecutionError {
            code: "INVALID_URL".to_string(),
            message: format!("Invalid URL format: {}", e),
        })?;

        // Check protocol restrictions
        match url.scheme() {
            "http" | "https" => {}
            _ => {
                return Err(ExecutionError {
                    code: "UNSUPPORTED_SCHEME".to_string(),
                    message: format!("Unsupported URL scheme: {}", url.scheme()),
                });
            }
        }

        let host = url.host_str().ok_or_else(|| ExecutionError {
            code: "INVALID_URL".to_string(),
            message: "URL must include a host".to_string(),
        })?;

        if Self::is_restricted_host(host) {
            return Err(ExecutionError {
                code: "UNSAFE_URL".to_string(),
                message: format!("URL targets a restricted host: {}", host),
            });
        }

        // Validate method if specified
        if let Some(ref method) = params.method {
            match method.to_uppercase().as_str() {
                "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" => {}
                _ => {
                    return Err(ExecutionError {
                        code: "INVALID_METHOD".to_string(),
                        message: format!("Unsupported HTTP method: {}", method),
                    });
                }
            }
        }

        // Validate timeout if specified
        if let Some(timeout) = params.timeout_ms {
            if timeout > 60000 {
                // 60 seconds max
                return Err(ExecutionError {
                    code: "TIMEOUT_EXCEEDED".to_string(),
                    message: "Timeout exceeds 60 second limit".to_string(),
                });
            }
        }

        debug!(
            "http.fetch.v1 parameters validated successfully for URL: {}",
            params.url
        );
        Ok(())
    }

    async fn execute(
        &self,
        intent: Intent,
        ctx: ExecCtx,
    ) -> Result<CapabilityResult, ExecutionError> {
        let start_time = std::time::Instant::now();
        let start_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u128;

        info!("Executing http.fetch.v1 for intent: {}", intent.id);

        // Parse parameters
        let params: smith_protocol::params::HttpFetchV1 = serde_json::from_value(intent.params)
            .map_err(|e| ExecutionError {
                code: "PARAM_PARSE_ERROR".to_string(),
                message: format!("Failed to parse parameters: {}", e),
            })?;

        // Check if URL is allowed
        if !self.is_url_allowed(&params.url, &ctx.scope.urls) {
            return Err(ExecutionError {
                code: "URL_DENIED".to_string(),
                message: format!("URL not in allowed list: {}", params.url),
            });
        }

        debug!("Making HTTP request to: {}", params.url);

        // Track allowlist hit
        let _allowlist_hit = AllowlistHit {
            resource_type: "url".to_string(),
            resource_id: params.url.clone(),
            operation: params.method.as_deref().unwrap_or("GET").to_string(),
            timestamp_ns: start_ns,
        };

        // Build HTTP request
        let method = params.method.as_deref().unwrap_or("GET");
        let mut request_builder = self.client.request(method.parse().unwrap(), &params.url);

        // Add headers if provided
        if let Some(headers) = params.headers {
            for (name, value) in headers {
                request_builder = request_builder.header(&name, &value);
            }
        }

        // Store body length before moving for network_tx_bytes calculation
        let body_length = params.body.as_ref().map(|b| b.len() as u64).unwrap_or(0);

        // Add body if provided
        if let Some(body) = params.body {
            request_builder = request_builder.body(body);
        }

        // Set timeout if specified
        if let Some(timeout_ms) = params.timeout_ms {
            request_builder = request_builder.timeout(Duration::from_millis(timeout_ms as u64));
        }

        // Execute request
        let request_result = request_builder.send().await;

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        match request_result {
            Ok(response) => {
                let status_code = response.status().as_u16();
                let response_headers: std::collections::HashMap<String, String> = response
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect();

                // Read response body
                let body_result = response.text().await;

                match body_result {
                    Ok(body) => {
                        let response_size = body.len() as u64;

                        info!(
                            "HTTP request completed: {} {} ({}ms)",
                            method, status_code, duration_ms
                        );

                        let output = json!({
                            "url": params.url,
                            "method": method,
                            "status_code": status_code,
                            "headers": response_headers,
                            "body": body,
                            "size_bytes": response_size,
                            "duration_ms": duration_ms
                        });

                        Ok(CapabilityResult {
                            status: ExecutionStatus::Ok,
                            output: Some(output),
                            error: None,
                            metadata: ExecutionMetadata {
                                pid: std::process::id(),
                                exit_code: Some(0),
                                duration_ms,
                                stdout_bytes: 0,
                                stderr_bytes: 0,
                                artifacts: vec![],
                            },
                            resource_usage: smith_protocol::ResourceUsage {
                                peak_memory_kb: 2048, // Estimate
                                cpu_time_ms: duration_ms as u32,
                                wall_time_ms: duration_ms as u32,
                                fd_count: 2,
                                disk_read_bytes: 0,
                                disk_write_bytes: 0,
                                network_tx_bytes: body_length,
                                network_rx_bytes: response_size,
                            },
                        })
                    }
                    Err(e) => {
                        warn!("Failed to read HTTP response body: {}", e);
                        Err(ExecutionError {
                            code: "RESPONSE_READ_ERROR".to_string(),
                            message: format!("Failed to read response body: {}", e),
                        })
                    }
                }
            }
            Err(e) => {
                warn!("HTTP request failed for {}: {}", params.url, e);

                let error_code = if e.is_timeout() {
                    "REQUEST_TIMEOUT"
                } else if e.is_connect() {
                    "CONNECTION_ERROR"
                } else {
                    "REQUEST_ERROR"
                };

                Err(ExecutionError {
                    code: error_code.to_string(),
                    message: format!("HTTP request failed: {}", e),
                })
            }
        }
    }

    fn describe(&self) -> CapabilitySpec {
        CapabilitySpec {
            name: self.name().to_string(),
            description: "Make HTTP/HTTPS requests with safety controls".to_string(),
            params_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "format": "uri",
                        "description": "HTTP/HTTPS URL to request",
                        "example": "https://api.example.com/data"
                    },
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                        "description": "HTTP method (default: GET)",
                        "example": "GET"
                    },
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": "HTTP headers to send",
                        "example": {"User-Agent": "Smith/1.0", "Accept": "application/json"}
                    },
                    "body": {
                        "type": "string",
                        "description": "Request body for POST/PUT requests",
                        "example": "{\"key\": \"value\"}"
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1000,
                        "maximum": 60000,
                        "description": "Request timeout in milliseconds (default: 30000, max: 60000)",
                        "example": 5000
                    }
                },
                "required": ["url"],
                "additionalProperties": false
            }),
            example_params: json!({
                "url": "https://httpbin.org/json",
                "method": "GET",
                "headers": {
                    "Accept": "application/json",
                    "User-Agent": "Smith-Executor/1.0"
                },
                "timeout_ms": 10000
            }),
            resource_requirements: ResourceRequirements {
                cpu_ms_typical: 50,
                memory_kb_max: 2048,
                network_access: true,
                filesystem_access: false,
                external_commands: false,
            },
            security_notes: vec![
                "Only HTTP and HTTPS protocols are supported".to_string(),
                "URLs must be in the execution allowlist".to_string(),
                "Request timeout is limited to 60 seconds".to_string(),
                "Response size is limited by available memory".to_string(),
                "All requests include User-Agent identification".to_string(),
            ],
        }
    }
}

impl HttpFetchV1Capability {
    const MAX_URL_LENGTH: usize = 1024;

    /// Check if a URL is allowed according to the execution scope
    fn is_url_allowed(&self, url: &str, allowed_urls: &[String]) -> bool {
        // If no specific URLs are configured, deny all requests for security
        if allowed_urls.is_empty() {
            return false;
        }

        // Check if URL matches any allowed pattern
        for allowed in allowed_urls {
            if url.starts_with(allowed) || allowed == "*" {
                return true;
            }
        }

        false
    }

    fn is_restricted_host(host: &str) -> bool {
        let stripped = host.trim_start_matches('[').trim_end_matches(']');
        let host_lower = stripped.to_ascii_lowercase();

        // Common loopback / local indicators
        if host_lower == "localhost"
            || host_lower.ends_with(".localhost")
            || host_lower == "127.0.0.1"
            || host_lower == "::1"
            || host_lower.starts_with("127.")
            || host_lower.contains("127.0.0.1")
            || host_lower == "0.0.0.0"
            || host_lower.ends_with(".local")
            || host_lower == "metadata.google.internal"
        {
            return true;
        }

        if let Some(ip) = Self::parse_potential_ip(&host_lower) {
            if Self::ip_is_restricted(&ip) {
                return true;
            }
        }

        false
    }

    fn parse_potential_ip(host: &str) -> Option<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(ip);
        }

        if let Some(stripped) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            if let Ok(value) = u32::from_str_radix(stripped, 16) {
                return Some(IpAddr::V4(Ipv4Addr::from(value)));
            }
        }

        if host.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(value) = host.parse::<u32>() {
                return Some(IpAddr::V4(Ipv4Addr::from(value)));
            }
        }

        if host.contains('.') {
            if let Some(ipv4) = Self::parse_ipv4_mixed_radix(host) {
                return Some(IpAddr::V4(ipv4));
            }
        }

        None
    }

    fn parse_ipv4_mixed_radix(host: &str) -> Option<Ipv4Addr> {
        let segments: Vec<&str> = host.split('.').collect();
        if segments.len() != 4 {
            return None;
        }

        let mut octets = [0u8; 4];
        for (idx, segment) in segments.iter().enumerate() {
            if segment.is_empty() {
                return None;
            }

            let (radix, digits) = if let Some(hex) = segment
                .strip_prefix("0x")
                .or_else(|| segment.strip_prefix("0X"))
            {
                (16, hex)
            } else if segment.starts_with('0') && segment.len() > 1 {
                (8, &segment[1..])
            } else {
                (10, *segment)
            };

            let value = u8::from_str_radix(digits, radix).ok()?;
            octets[idx] = value;
        }

        Some(Ipv4Addr::from(octets))
    }

    fn ip_is_restricted(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 0
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_unique_local()
                    || v6.is_multicast()
                    || v6.is_unicast_link_local()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Capability as ProtoCapability;

    #[tokio::test]
    async fn test_http_fetch_v1_validation() {
        let capability = HttpFetchV1Capability::new();

        // Valid intent
        let valid_intent = Intent::new(
            ProtoCapability::HttpFetchV1,
            "test".to_string(),
            json!({"url": "https://example.com"}),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&valid_intent).is_ok());

        // Invalid intent - empty URL
        let invalid_intent = Intent::new(
            ProtoCapability::HttpFetchV1,
            "test".to_string(),
            json!({"url": ""}),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&invalid_intent).is_err());

        // Invalid intent - bad URL scheme
        let invalid_scheme = Intent::new(
            ProtoCapability::HttpFetchV1,
            "test".to_string(),
            json!({"url": "ftp://example.com"}),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&invalid_scheme).is_err());

        // Loopback IPv4 should be rejected
        let loopback_intent = Intent::new(
            ProtoCapability::HttpFetchV1,
            "test".to_string(),
            json!({"url": "http://127.0.0.1"}),
            30000,
            "test-signer".to_string(),
        );
        assert!(capability.validate(&loopback_intent).is_err());

        // Loopback IPv6 should be rejected
        let ipv6_loopback_intent = Intent::new(
            ProtoCapability::HttpFetchV1,
            "test".to_string(),
            json!({"url": "http://[::1]"}),
            30000,
            "test-signer".to_string(),
        );
        assert!(capability.validate(&ipv6_loopback_intent).is_err());
    }

    #[test]
    fn test_url_allowed() {
        let capability = HttpFetchV1Capability::new();

        // Empty allowlist denies everything
        assert!(!capability.is_url_allowed("https://example.com", &[]));

        // Specific allowlist
        let allowed = vec![
            "https://api.example.com".to_string(),
            "https://httpbin.org".to_string(),
        ];
        assert!(capability.is_url_allowed("https://api.example.com/data", &allowed));
        assert!(capability.is_url_allowed("https://httpbin.org/json", &allowed));
        assert!(!capability.is_url_allowed("https://malicious.com", &allowed));

        // Wildcard allowlist
        let wildcard = vec!["*".to_string()];
        assert!(capability.is_url_allowed("https://any.com", &wildcard));
    }

    #[test]
    fn test_describe() {
        let capability = HttpFetchV1Capability::new();
        let spec = capability.describe();

        assert_eq!(spec.name, "http.fetch.v1");
        assert!(spec.resource_requirements.network_access);
        assert!(!spec.resource_requirements.filesystem_access);
    }
}
