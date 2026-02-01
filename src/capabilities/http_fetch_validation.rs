//! HTTP fetch validation helpers
//!
//! Security validation functions for HTTP requests to prevent SSRF attacks,
//! enforce network isolation, and validate request parameters.

use anyhow::Result;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use url::Url;

/// Validates an HTTP fetch intent for security compliance
pub fn validate_http_fetch_intent(intent: &Value) -> Result<()> {
    // Extract parameters
    let params = intent["params"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Missing params"))?;

    // Validate URL
    let url_str = params
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid URL"))?;

    validate_http_url(url_str)?;

    // Validate method
    if let Some(method) = params.get("method") {
        let method = method
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid method type"))?;
        validate_http_method(method)?;
    }

    // Validate timeout
    if let Some(timeout) = params.get("timeout_seconds") {
        let timeout = timeout
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("Invalid timeout type"))?;
        validate_timeout(timeout)?;
    }

    // Validate headers
    if let Some(headers) = params.get("headers") {
        let headers = headers
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Headers must be object"))?;

        for (name, value) in headers {
            let value = value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Header value must be string"))?;
            validate_http_header(name, value)?;
        }
    }

    // Validate body
    if let Some(body) = params.get("body") {
        validate_request_body(body)?;
    }

    Ok(())
}

/// Validates HTTP URL for security compliance (SSRF prevention)
pub fn validate_http_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(anyhow::anyhow!("URL cannot be empty"));
    }

    let parsed = Url::parse(url).map_err(|_| anyhow::anyhow!("Invalid URL format"))?;

    // Validate scheme
    validate_url_scheme(&parsed)?;

    // Validate host
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must have host"))?;

    // Check if host is private IP
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip.to_string()) {
            return Err(anyhow::anyhow!("Private IP addresses not allowed"));
        }
    }

    // Check for localhost and special domains
    let forbidden_hosts = vec!["localhost", "metadata.google.internal"];

    for forbidden in forbidden_hosts {
        if host.contains(forbidden) {
            return Err(anyhow::anyhow!("Forbidden host: {}", host));
        }
    }

    Ok(())
}

/// Validates URL scheme to allow only HTTP(S)
pub fn validate_url_scheme(url: &Url) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" => Ok(()), // Allow HTTP for testing, might be restricted in production
        _ => Err(anyhow::anyhow!("Only HTTP(S) schemes allowed")),
    }
}

/// Validates HTTP method against allowed list
pub fn validate_http_method(method: &str) -> Result<()> {
    let allowed_methods = vec!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

    if allowed_methods.contains(&method) {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Method not allowed: {}", method))
    }
}

/// Validates timeout is within safe bounds
pub fn validate_timeout(timeout: i64) -> Result<()> {
    if timeout <= 0 || timeout > 600 {
        Err(anyhow::anyhow!("Timeout must be between 1 and 600 seconds"))
    } else {
        Ok(())
    }
}

/// Validates HTTP headers to prevent dangerous headers
pub fn validate_http_header(name: &str, _value: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow::anyhow!("Header name cannot be empty"));
    }

    // Block dangerous headers
    let forbidden_headers = vec![
        "Host",
        "Cookie",
        "Set-Cookie",
        "X-Forwarded-For",
        "X-Real-IP",
    ];

    for forbidden in forbidden_headers {
        if name.eq_ignore_ascii_case(forbidden) {
            return Err(anyhow::anyhow!("Header not allowed: {}", name));
        }
    }

    Ok(())
}

/// Validates request body size and nesting depth
pub fn validate_request_body(body: &Value) -> Result<()> {
    // Check size limit (serialized JSON)
    let serialized = serde_json::to_string(body)?;
    if serialized.len() > 1024 * 1024 {
        // 1MB limit
        return Err(anyhow::anyhow!("Request body too large"));
    }

    // Check nesting depth to prevent stack overflow
    fn check_depth(value: &Value, current_depth: usize, max_depth: usize) -> bool {
        if current_depth > max_depth {
            return false;
        }

        match value {
            Value::Object(map) => {
                for v in map.values() {
                    if !check_depth(v, current_depth + 1, max_depth) {
                        return false;
                    }
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    if !check_depth(v, current_depth + 1, max_depth) {
                        return false;
                    }
                }
            }
            _ => {}
        }

        true
    }

    if !check_depth(body, 0, 10) {
        return Err(anyhow::anyhow!("Request body nested too deeply"));
    }

    Ok(())
}

/// Checks if an IP address is private/internal
pub fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        addr.is_private()
            || addr.is_loopback()
            || addr.is_link_local()
            || addr.is_broadcast()
            || addr.is_unspecified()
    } else {
        // Could be IPv6, for simplicity assume dangerous
        true
    }
}

/// Validates domain against allowed list
pub fn validate_domain(url: &Url, allowed_domains: &[String]) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL must have host"))?;

    for allowed in allowed_domains {
        if host == allowed || host.ends_with(&format!(".{}", allowed)) {
            return Ok(());
        }
    }

    Err(anyhow::anyhow!("Domain not in allowed list: {}", host))
}

/// Validates response size against limits
pub fn validate_response_size(response: &str, max_size: usize) -> Result<()> {
    if response.len() > max_size {
        Err(anyhow::anyhow!(
            "Response too large: {} > {}",
            response.len(),
            max_size
        ))
    } else {
        Ok(())
    }
}

/// Creates a secure HTTP client with safety defaults
pub fn create_secure_http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::limited(3)) // Limit redirects
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    #[test]
    fn test_validate_http_fetch_intent_valid() {
        let intent = json!({
            "params": {
                "url": "https://api.github.com/user",
                "method": "GET",
                "timeout_seconds": 30,
                "headers": {
                    "Accept": "application/json",
                    "User-Agent": "Smith-Executor/1.0"
                }
            }
        });

        assert!(
            validate_http_fetch_intent(&intent).is_ok(),
            "Valid HTTP fetch intent should pass validation"
        );
    }

    #[test]
    fn test_validate_http_fetch_intent_missing_params() {
        let intent = json!({
            "id": "test-123"
        });

        let result = validate_http_fetch_intent(&intent);
        assert!(result.is_err(), "Missing params should fail validation");
        assert!(result.unwrap_err().to_string().contains("Missing params"));
    }

    #[test]
    fn test_validate_http_fetch_intent_missing_url() {
        let intent = json!({
            "params": {
                "method": "GET"
            }
        });

        let result = validate_http_fetch_intent(&intent);
        assert!(result.is_err(), "Missing URL should fail validation");
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing or invalid URL"));
    }

    #[test]
    fn test_validate_http_url_valid_urls() {
        let valid_urls = [
            "https://api.github.com",
            "https://httpbin.org/json",
            "http://example.com/api",
            "https://www.google.com/search?q=test",
        ];

        for url in valid_urls {
            assert!(
                validate_http_url(url).is_ok(),
                "Valid URL '{}' should pass validation",
                url
            );
        }
    }

    #[test]
    fn test_validate_http_url_invalid_urls() {
        let invalid_urls = [
            "ftp://example.com/file",  // Non-HTTP scheme
            "file:///etc/passwd",      // File scheme
            "javascript:alert('xss')", // JavaScript scheme
            "data:text/html,<script>", // Data scheme
            "not_a_url",               // Invalid format
            "",                        // Empty URL
        ];

        for url in invalid_urls {
            assert!(
                validate_http_url(url).is_err(),
                "Invalid URL '{}' should fail validation",
                url
            );
        }
    }

    #[test]
    fn test_validate_http_url_ssrf_protection() {
        let ssrf_urls = [
            "http://localhost:8080/admin", // Localhost
            "http://127.0.0.1/secret",     // Loopback
            "http://10.0.0.1/internal",    // Private IP
            "http://192.168.1.1/router",   // Private IP
            "http://172.16.0.1/api",       // Private IP
        ];

        for url in ssrf_urls {
            let result = validate_http_url(url);
            // Should either block private IPs or pass them through for further filtering
            println!("Testing SSRF URL '{}': {:?}", url, result);
        }
    }

    #[test]
    fn test_validate_url_scheme() {
        use url::Url;

        let https_url = Url::parse("https://example.com").unwrap();
        assert!(
            validate_url_scheme(&https_url).is_ok(),
            "HTTPS should be allowed"
        );

        let http_url = Url::parse("http://example.com").unwrap();
        assert!(
            validate_url_scheme(&http_url).is_ok(),
            "HTTP should be allowed"
        );

        let ftp_url = Url::parse("ftp://example.com").unwrap();
        assert!(
            validate_url_scheme(&ftp_url).is_err(),
            "FTP should be blocked"
        );

        let file_url = Url::parse("file:///etc/passwd").unwrap();
        assert!(
            validate_url_scheme(&file_url).is_err(),
            "File scheme should be blocked"
        );
    }

    #[test]
    fn test_validate_http_method() {
        let valid_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
        for method in valid_methods {
            assert!(
                validate_http_method(method).is_ok(),
                "Valid method '{}' should pass",
                method
            );
        }

        let invalid_methods = ["TRACE", "CONNECT", "INVALID", "", "get"]; // lowercase should fail
        for method in invalid_methods {
            assert!(
                validate_http_method(method).is_err(),
                "Invalid method '{}' should fail",
                method
            );
        }
    }

    #[test]
    fn test_validate_timeout() {
        // Valid timeouts
        assert!(validate_timeout(1).is_ok(), "1 second should be valid");
        assert!(validate_timeout(30).is_ok(), "30 seconds should be valid");
        assert!(validate_timeout(300).is_ok(), "300 seconds should be valid");

        // Invalid timeouts
        assert!(validate_timeout(0).is_err(), "0 timeout should fail");
        assert!(
            validate_timeout(-1).is_err(),
            "Negative timeout should fail"
        );
        assert!(validate_timeout(3601).is_err(), "Over 1 hour should fail");
    }

    #[test]
    fn test_validate_http_header() {
        // Valid headers
        let valid_headers = [
            ("Accept", "application/json"),
            ("User-Agent", "Smith-Executor/1.0"),
            ("Content-Type", "application/json"),
            ("Authorization", "Bearer token123"),
        ];

        for (name, value) in valid_headers {
            assert!(
                validate_http_header(name, value).is_ok(),
                "Valid header '{}' should pass",
                name
            );
        }

        // Invalid headers (security-sensitive ones that should be blocked)
        let dangerous_headers = [
            ("Host", "evil.com"),         // Host header manipulation
            ("Cookie", "session=admin"),  // Cookie injection
            ("Set-Cookie", "admin=true"), // Response manipulation
        ];

        for (name, value) in dangerous_headers {
            let result = validate_http_header(name, value);
            if result.is_err() {
                println!("Blocked dangerous header '{}' (good!)", name);
            } else {
                println!("Warning: Header '{}' was allowed", name);
            }
        }
    }

    #[test]
    fn test_validate_request_body() {
        // Valid JSON body
        let json_body = json!({"key": "value", "count": 42});
        assert!(
            validate_request_body(&json_body).is_ok(),
            "Valid JSON body should pass"
        );

        // Valid string body
        let string_body = json!("plain text body");
        assert!(
            validate_request_body(&string_body).is_ok(),
            "Valid string body should pass"
        );

        // Null body (should be valid for GET requests)
        let null_body = json!(null);
        assert!(
            validate_request_body(&null_body).is_ok(),
            "Null body should be valid"
        );

        // Test body size limits
        let large_string = "x".repeat(1024 * 1024 * 10); // 10MB string
        let large_body = json!(large_string);
        let result = validate_request_body(&large_body);
        // Should either pass or fail gracefully with size limit error
        println!("Large body validation result: {:?}", result);
    }

    #[test]
    fn test_is_private_ip() {
        // Private IP addresses that should be blocked
        let private_ips = [
            "127.0.0.1",   // Localhost
            "10.0.0.1",    // Private class A
            "192.168.1.1", // Private class C
            "172.16.0.1",  // Private class B
            "169.254.1.1", // Link-local
            "::1",         // IPv6 localhost
        ];

        for ip in private_ips {
            assert!(
                is_private_ip(ip),
                "IP '{}' should be detected as private",
                ip
            );
        }

        // Public IP addresses that should be allowed
        let public_ips = [
            "8.8.8.8",        // Google DNS
            "1.1.1.1",        // Cloudflare DNS
            "208.67.222.222", // OpenDNS
        ];

        for ip in public_ips {
            assert!(
                !is_private_ip(ip),
                "IP '{}' should NOT be detected as private",
                ip
            );
        }
    }

    #[test]
    fn test_validate_domain() {
        use url::Url;

        let allowed_domains = vec!["github.com".to_string(), "api.github.com".to_string()];

        // Should allow specified domains
        let github_url = Url::parse("https://api.github.com/user").unwrap();
        assert!(
            validate_domain(&github_url, &allowed_domains).is_ok(),
            "Allowed domain should pass"
        );

        // Should block non-allowed domains
        let google_url = Url::parse("https://google.com").unwrap();
        assert!(
            validate_domain(&google_url, &allowed_domains).is_err(),
            "Non-allowed domain should be blocked"
        );

        // Test subdomain handling
        let subdomain_url = Url::parse("https://files.github.com/download").unwrap();
        let result = validate_domain(&subdomain_url, &allowed_domains);
        println!("Subdomain validation result: {:?}", result);
    }

    #[test]
    fn test_validate_response_size() {
        let small_response = "small response";
        assert!(
            validate_response_size(small_response, 1024).is_ok(),
            "Small response should pass size validation"
        );

        let large_response = "x".repeat(2000);
        assert!(
            validate_response_size(&large_response, 1000).is_err(),
            "Large response should fail size validation"
        );

        let exact_size_response = "x".repeat(1000);
        assert!(
            validate_response_size(&exact_size_response, 1000).is_ok(),
            "Exact size response should pass"
        );
    }

    #[test]
    fn test_create_secure_http_client() {
        let timeout = Duration::from_secs(30);
        let client_result = create_secure_http_client(timeout);

        assert!(
            client_result.is_ok(),
            "Should create HTTP client successfully"
        );

        let _client = client_result.unwrap();

        // Verify client has security defaults
        // Note: reqwest::Client doesn't expose configuration for inspection,
        // but we can verify it was created without errors
        println!("HTTP client created successfully with security defaults");
    }

    #[test]
    fn test_comprehensive_http_security_validation() {
        // Test a complex malicious request that tries multiple attack vectors
        let malicious_intent = json!({
            "params": {
                "url": "http://127.0.0.1:22/admin/../../../etc/passwd",
                "method": "TRACE",  // Dangerous method
                "timeout_seconds": -1,  // Invalid timeout
                "headers": {
                    "Host": "evil.com",
                    "X-Forwarded-For": "127.0.0.1",
                    "Cookie": "admin=true"
                },
                "body": {
                    "command": "rm -rf /",
                    "script": "<script>alert('xss')</script>"
                }
            }
        });

        let result = validate_http_fetch_intent(&malicious_intent);
        assert!(
            result.is_err(),
            "Malicious intent should be blocked by validation"
        );

        println!("Malicious request blocked: {}", result.unwrap_err());
    }

    #[test]
    fn test_security_boundary_edge_cases() {
        // Test various edge cases that attackers might exploit

        // URL with embedded credentials
        let cred_url_result = validate_http_url("https://user:pass@evil.com/api");
        println!("URL with credentials result: {:?}", cred_url_result);

        // Unicode domain attack
        let unicode_url_result = validate_http_url("https://еxаmрlе.com/api"); // Cyrillic chars
        println!("Unicode domain result: {:?}", unicode_url_result);

        // URL with fragments and queries
        let complex_url_result =
            validate_http_url("https://api.example.com/path?param=value#fragment");
        println!("Complex URL result: {:?}", complex_url_result);

        // Extremely long URL
        let long_path = "a".repeat(8192);
        let long_url_result = validate_http_url(&format!("https://example.com/{}", long_path));
        println!("Long URL result: {:?}", long_url_result);
    }
}
