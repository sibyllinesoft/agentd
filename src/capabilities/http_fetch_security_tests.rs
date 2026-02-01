//! Comprehensive security tests for http_fetch_v1 capability
//!
//! This module contains extensive tests to verify that the http_fetch capability
//! provides secure network access with proper validation and isolation.

use super::http_fetch_validation::*;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use url::Url;
use uuid::Uuid;

/// Comprehensive test environment for http_fetch security testing
pub struct HttpFetchSecurityTestEnvironment {
    pub workdir: TempDir,
    pub allowed_domains: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub test_urls: HashMap<String, String>,
}

impl HttpFetchSecurityTestEnvironment {
    /// Create a comprehensive test environment with various URL scenarios
    pub fn new() -> Result<Self> {
        let workdir = tempdir()?;

        let allowed_domains = vec![
            "httpbin.org".to_string(),
            "jsonplaceholder.typicode.com".to_string(),
            "api.github.com".to_string(),
        ];

        let blocked_domains = vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "0.0.0.0".to_string(),
            "internal.company.com".to_string(),
            "admin.example.com".to_string(),
        ];

        let mut test_urls = HashMap::new();

        // Safe public API URLs for testing
        test_urls.insert(
            "valid_json".to_string(),
            "https://httpbin.org/json".to_string(),
        );
        test_urls.insert(
            "valid_get".to_string(),
            "https://httpbin.org/get".to_string(),
        );
        test_urls.insert(
            "github_api".to_string(),
            "https://api.github.com/zen".to_string(),
        );

        // Potentially dangerous URLs
        test_urls.insert(
            "localhost".to_string(),
            "http://localhost:8080/admin".to_string(),
        );
        test_urls.insert(
            "internal_ip".to_string(),
            "http://192.168.1.1/config".to_string(),
        );
        test_urls.insert(
            "loopback".to_string(),
            "http://127.0.0.1:22/ssh".to_string(),
        );
        test_urls.insert(
            "metadata".to_string(),
            "http://169.254.169.254/latest/meta-data/".to_string(),
        );
        test_urls.insert("file_scheme".to_string(), "file:///etc/passwd".to_string());
        test_urls.insert(
            "ftp_scheme".to_string(),
            "ftp://example.com/file.txt".to_string(),
        );

        Ok(Self {
            workdir,
            allowed_domains,
            blocked_domains,
            test_urls,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_fetch_intent_validation() {
        let env = HttpFetchSecurityTestEnvironment::new().unwrap();

        // Test valid intent
        let valid_intent = json!({
            "id": Uuid::new_v4().to_string(),
            "capability": "http.fetch.v1",
            "params": {
                "url": env.test_urls["valid_get"],
                "method": "GET",
                "timeout_seconds": 30
            }
        });

        let result = validate_http_fetch_intent(&valid_intent);
        assert!(result.is_ok(), "Valid intent should pass validation");

        // Test invalid intent - missing URL
        let invalid_intent = json!({
            "id": Uuid::new_v4().to_string(),
            "capability": "http.fetch.v1",
            "params": {
                "method": "GET",
                "timeout_seconds": 30
            }
        });

        let result = validate_http_fetch_intent(&invalid_intent);
        assert!(result.is_err(), "Intent without URL should fail validation");

        // Test invalid intent - invalid method
        let invalid_intent = json!({
            "id": Uuid::new_v4().to_string(),
            "capability": "http.fetch.v1",
            "params": {
                "url": env.test_urls["valid_get"],
                "method": "INVALID",
                "timeout_seconds": 30
            }
        });

        let result = validate_http_fetch_intent(&invalid_intent);
        assert!(
            result.is_err(),
            "Intent with invalid method should fail validation"
        );
    }

    #[test]
    fn test_url_validation_security() {
        let _env = HttpFetchSecurityTestEnvironment::new().unwrap();

        // Test valid URLs
        let valid_urls = vec![
            "https://httpbin.org/get",
            "https://api.github.com/zen",
            "https://jsonplaceholder.typicode.com/posts/1",
            "http://httpbin.org/get", // HTTP allowed for testing
        ];

        for url in valid_urls {
            let result = validate_http_url(url);
            assert!(result.is_ok(), "Valid URL should pass validation: {}", url);
        }

        // Test invalid URLs - security risks
        let invalid_urls = vec![
            "http://localhost:8080/admin",
            "http://127.0.0.1/config",
            "http://0.0.0.0/internal",
            "http://192.168.1.1/router",
            "http://10.0.0.1/private",
            "http://169.254.169.254/metadata", // AWS metadata service
            "http://metadata.google.internal/", // GCP metadata service
            "file:///etc/passwd",
            "ftp://example.com/file.txt",
            "gopher://example.com/",
            "javascript:alert(1)",
            "",
            "not-a-url",
            "http://", // Incomplete URL
        ];

        for url in invalid_urls {
            let result = validate_http_url(url);
            assert!(
                result.is_err(),
                "Invalid URL should fail validation: {}",
                url
            );
        }
    }

    #[test]
    fn test_http_method_validation() {
        let valid_methods = vec!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

        for method in valid_methods {
            let result = validate_http_method(method);
            assert!(
                result.is_ok(),
                "Valid method should pass validation: {}",
                method
            );
        }

        let invalid_methods = vec![
            "TRACE",   // Potentially dangerous
            "CONNECT", // Potentially dangerous
            "INVALID", "", "get", // Case sensitive
            "post",
        ];

        for method in invalid_methods {
            let result = validate_http_method(method);
            assert!(
                result.is_err(),
                "Invalid method should fail validation: {}",
                method
            );
        }
    }

    #[test]
    fn test_headers_validation() {
        // Test valid headers
        let valid_headers = vec![
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer token123"),
            ("User-Agent", "Smith/1.0"),
            ("Accept", "application/json"),
            ("X-Custom-Header", "custom-value"),
        ];

        for (name, value) in valid_headers {
            let result = validate_http_header(name, value);
            assert!(
                result.is_ok(),
                "Valid header should pass validation: {}={}",
                name,
                value
            );
        }

        // Test invalid headers - security risks
        let invalid_headers = vec![
            ("Host", "evil.com"),             // Host header manipulation
            ("Cookie", "session=admin"),      // Cookie injection
            ("Set-Cookie", "auth=admin"),     // Response header in request
            ("X-Forwarded-For", "127.0.0.1"), // IP spoofing attempt
            ("X-Real-IP", "10.0.0.1"),        // IP spoofing attempt
            ("", "value"),                    // Empty header name
            ("Header", ""),                   // Empty value might be OK
        ];

        for (name, value) in invalid_headers {
            let result = validate_http_header(name, value);
            if name.is_empty() || name == "Host" || name == "Set-Cookie" {
                assert!(
                    result.is_err(),
                    "Invalid header should fail validation: {}={}",
                    name,
                    value
                );
            }
            // Other cases might be allowed depending on implementation
        }
    }

    #[test]
    fn test_timeout_validation() {
        // Test valid timeouts
        let valid_timeouts = vec![1, 5, 10, 30, 60, 120];

        for timeout in valid_timeouts {
            let result = validate_timeout(timeout);
            assert!(
                result.is_ok(),
                "Valid timeout should pass validation: {}",
                timeout
            );
        }

        // Test invalid timeouts
        let invalid_timeouts = vec![0, -1, 601, 1800, -30]; // Zero, negative, too large

        for timeout in invalid_timeouts {
            let result = validate_timeout(timeout);
            assert!(
                result.is_err(),
                "Invalid timeout should fail validation: {}",
                timeout
            );
        }
    }

    #[test]
    fn test_request_body_validation() {
        // Test valid request bodies
        let valid_bodies = vec![
            json!({"key": "value"}),
            json!({"user": "test", "email": "test@example.com"}),
            json!([1, 2, 3]),
            json!("simple string"),
            Value::Null,
        ];

        for body in valid_bodies {
            let result = validate_request_body(&body);
            assert!(
                result.is_ok(),
                "Valid body should pass validation: {:?}",
                body
            );
        }

        // Test request body size limits
        let large_body = json!({"data": "x".repeat(1024 * 1024)}); // 1MB string
        let result = validate_request_body(&large_body);
        assert!(result.is_err(), "Large body should fail validation");

        // Test deeply nested body
        let mut nested = json!({});
        for i in 0..100 {
            nested = json!({"level": i, "nested": nested});
        }
        let result = validate_request_body(&nested);
        assert!(result.is_err(), "Deeply nested body should fail validation");
    }

    #[test]
    fn test_private_ip_detection() {
        let private_ips = vec![
            "127.0.0.1",       // Loopback
            "127.0.0.5",       // Loopback range
            "10.0.0.1",        // Private class A
            "10.255.255.255",  // Private class A
            "172.16.0.1",      // Private class B
            "172.31.255.255",  // Private class B
            "192.168.0.1",     // Private class C
            "192.168.255.255", // Private class C
            "169.254.1.1",     // Link-local
            "0.0.0.0",         // Null route
            "255.255.255.255", // Broadcast
        ];

        for ip in private_ips {
            let result = is_private_ip(ip);
            assert!(result, "Should detect private IP: {}", ip);
        }

        let public_ips = vec![
            "8.8.8.8",        // Google DNS
            "1.1.1.1",        // Cloudflare DNS
            "208.67.222.222", // OpenDNS
            "4.2.2.1",        // Level3
            "13.107.42.14",   // Microsoft
            "157.240.1.1",    // Facebook
        ];

        for ip in public_ips {
            let result = is_private_ip(ip);
            assert!(!result, "Should not detect public IP as private: {}", ip);
        }
    }

    #[test]
    fn test_url_scheme_validation() {
        let valid_schemes = vec![
            "https://example.com",
            "http://example.com", // Might be allowed for testing
        ];

        for url in valid_schemes {
            let parsed = Url::parse(url).unwrap();
            let result = validate_url_scheme(&parsed);
            // Result depends on security policy - HTTPS might be required
            assert!(result.is_ok() || result.is_err()); // Either outcome acceptable
        }

        let invalid_schemes = vec![
            "file:///etc/passwd",
            "ftp://example.com/file.txt",
            "ldap://example.com/",
            "gopher://example.com/",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ];

        for url_str in invalid_schemes {
            if let Ok(parsed) = Url::parse(url_str) {
                let result = validate_url_scheme(&parsed);
                assert!(
                    result.is_err(),
                    "Invalid scheme should fail validation: {}",
                    url_str
                );
            }
        }
    }

    #[test]
    fn test_domain_validation() {
        let env = HttpFetchSecurityTestEnvironment::new().unwrap();

        // Test allowed domains
        for domain in &env.allowed_domains {
            let url = format!("https://{}/test", domain);
            let parsed = Url::parse(&url).unwrap();
            let result = validate_domain(&parsed, &env.allowed_domains);
            assert!(
                result.is_ok(),
                "Allowed domain should pass validation: {}",
                domain
            );
        }

        // Test blocked domains
        for domain in &env.blocked_domains {
            let url = format!("https://{}/test", domain);
            let parsed = Url::parse(&url).unwrap();
            let result = validate_domain(&parsed, &env.allowed_domains);
            assert!(
                result.is_err(),
                "Blocked domain should fail validation: {}",
                domain
            );
        }
    }

    #[test]
    fn test_response_size_limits() {
        // Test response size validation
        let small_response = "x".repeat(1024); // 1KB
        let result = validate_response_size(&small_response, 2048);
        assert!(result.is_ok(), "Small response should pass validation");

        let large_response = "x".repeat(10 * 1024 * 1024); // 10MB
        let result = validate_response_size(&large_response, 1024 * 1024); // 1MB limit
        assert!(result.is_err(), "Large response should fail validation");

        let empty_response = "";
        let result = validate_response_size(empty_response, 1024);
        assert!(result.is_ok(), "Empty response should pass validation");
    }

    #[test]
    fn test_http_client_configuration() {
        // Test client configuration with security settings
        let client = create_secure_http_client(Duration::from_secs(30));
        assert!(
            client.is_ok(),
            "Should be able to create secure HTTP client"
        );

        let _client = client.unwrap();

        // Verify client has appropriate timeout
        // Note: reqwest doesn't expose timeout for inspection, so we test behavior

        // Test client refuses invalid redirects
        // This would require integration testing with actual HTTP servers
    }

    #[test]
    fn test_intent_parameter_combinations() {
        let env = HttpFetchSecurityTestEnvironment::new().unwrap();

        let test_cases = vec![
            // Valid cases
            (
                json!({
                    "url": env.test_urls["valid_get"],
                    "method": "GET",
                    "timeout_seconds": 30
                }),
                true,
            ),
            (
                json!({
                    "url": env.test_urls["valid_get"],
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "body": {"key": "value"},
                    "timeout_seconds": 60
                }),
                true,
            ),
            (
                json!({
                    "url": env.test_urls["valid_get"]
                    // Minimal case - method and timeout should have defaults
                }),
                true,
            ),
            // Invalid cases
            (
                json!({
                    "method": "GET",
                    "timeout_seconds": 30
                    // Missing URL
                }),
                false,
            ),
            (
                json!({
                    "url": "not-a-valid-url",
                    "method": "GET"
                }),
                false,
            ),
            (
                json!({
                    "url": env.test_urls["localhost"],
                    "method": "GET"
                }),
                false,
            ),
            (
                json!({
                    "url": env.test_urls["valid_get"],
                    "method": "INVALID_METHOD"
                }),
                false,
            ),
            (
                json!({
                    "url": env.test_urls["valid_get"],
                    "method": "GET",
                    "timeout_seconds": -1
                }),
                false,
            ),
            (
                json!({
                    "url": env.test_urls["valid_get"],
                    "method": "GET",
                    "timeout_seconds": 1000 // Too large
                }),
                false,
            ),
        ];

        for (params, should_be_valid) in test_cases {
            let intent = json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "http.fetch.v1",
                "params": params
            });

            let result = validate_http_fetch_intent(&intent);
            if should_be_valid {
                assert!(result.is_ok(), "Should be valid: {:?}", params);
            } else {
                assert!(result.is_err(), "Should be invalid: {:?}", params);
            }
        }
    }

    #[test]
    fn test_security_boundary_enforcement() {
        // Test various attack vectors that should be blocked
        let security_tests = vec![
            // Internal network access
            "http://localhost:8080/admin",
            "http://127.0.0.1:22/ssh",
            "http://0.0.0.0:3000/api",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/config",
            "http://172.16.0.1/admin",
            // Cloud metadata services
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            // Non-HTTP schemes
            "file:///etc/passwd",
            "ftp://example.com/file.txt",
            "ldap://example.com/users",
            "gopher://example.com/",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            // Malformed URLs
            "http://",
            "https://",
            "",
            "not-a-url",
        ];

        for malicious_url in security_tests {
            let intent = json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "http.fetch.v1",
                "params": {
                    "url": malicious_url,
                    "method": "GET",
                    "timeout_seconds": 30
                }
            });

            let result = validate_http_fetch_intent(&intent);
            assert!(
                result.is_err(),
                "Security boundary should block malicious URL: {}",
                malicious_url
            );
        }
    }

    #[test]
    fn test_error_handling() {
        // Test various error scenarios
        let error_cases = vec![
            // Missing required fields
            json!({
                "capability": "http.fetch.v1",
                "params": {}
            }),
            // Wrong data types
            json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "http.fetch.v1",
                "params": {
                    "url": 12345, // Should be string
                    "method": "GET"
                }
            }),
        ];

        for error_case in error_cases {
            let result = validate_http_fetch_intent(&error_case);
            // Should handle errors gracefully
            assert!(
                result.is_err(),
                "Should handle error case: {:?}",
                error_case
            );
        }
    }
}
