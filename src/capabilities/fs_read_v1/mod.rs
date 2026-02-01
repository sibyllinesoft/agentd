use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use smith_protocol::{
    AllowlistHit, CapabilitySpec, ExecutionError, ExecutionStatus, Intent, ResourceRequirements,
};
use std::path::{Component, Path};
use tokio::fs;
use tracing::{debug, info, warn};

use crate::capability::{Capability, CapabilityResult, ExecCtx, ExecutionMetadata};

/// FsReadV1 capability for reading files from the filesystem
pub struct FsReadV1Capability;

impl FsReadV1Capability {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Capability for FsReadV1Capability {
    fn name(&self) -> &'static str {
        "fs.read.v1"
    }

    fn validate(&self, intent: &Intent) -> Result<(), ExecutionError> {
        // Validate that this is a fs.read.v1 intent
        if intent.capability != smith_protocol::Capability::FsReadV1 {
            return Err(ExecutionError {
                code: "CAPABILITY_MISMATCH".to_string(),
                message: format!("Expected fs.read.v1, got {}", intent.capability),
            });
        }

        // Parse and validate parameters
        if let serde_json::Value::Object(ref map) = intent.params {
            for key in map.keys() {
                match key.as_str() {
                    "path" | "max_bytes" | "follow_symlinks" => {}
                    unexpected => {
                        return Err(ExecutionError {
                            code: "INVALID_PARAMS".to_string(),
                            message: format!("Unsupported parameter provided: {}", unexpected),
                        });
                    }
                }
            }
        }

        let params: smith_protocol::params::FsReadV1 =
            serde_json::from_value(intent.params.clone()).map_err(|e| ExecutionError {
                code: "INVALID_PARAMS".to_string(),
                message: format!("Failed to parse fs.read.v1 parameters: {}", e),
            })?;

        // Validate path
        if params.path.is_empty() {
            return Err(ExecutionError {
                code: "INVALID_PATH".to_string(),
                message: "Path cannot be empty".to_string(),
            });
        }

        if params.path.len() > Self::MAX_PATH_LENGTH {
            return Err(ExecutionError {
                code: "INVALID_PATH".to_string(),
                message: format!(
                    "Path length exceeds maximum allowed {} characters",
                    Self::MAX_PATH_LENGTH
                ),
            });
        }

        // Check for null bytes in path
        let decoded_variants = Self::decoded_path_variants(&params.path);

        if decoded_variants
            .iter()
            .any(|variant| variant.contains('\0'))
        {
            return Err(ExecutionError {
                code: "INVALID_PATH".to_string(),
                message: "Path cannot contain null bytes".to_string(),
            });
        }

        // Check for dangerous paths
        if let Some(reason) = decoded_variants
            .iter()
            .filter_map(|variant| Self::path_danger_reason(variant))
            .next()
        {
            return Err(ExecutionError {
                code: "UNSAFE_PATH".to_string(),
                message: reason.to_string(),
            });
        }

        // Validate max_bytes if specified
        if let Some(max_bytes) = params.max_bytes {
            if max_bytes > 10 * 1024 * 1024 {
                // 10MB limit
                return Err(ExecutionError {
                    code: "LIMIT_EXCEEDED".to_string(),
                    message: "max_bytes exceeds 10MB limit".to_string(),
                });
            }
        }

        debug!(
            "fs.read.v1 parameters validated successfully for path: {}",
            params.path
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

        info!("Executing fs.read.v1 for intent: {}", intent.id);

        // Parse parameters
        let params: smith_protocol::params::FsReadV1 = serde_json::from_value(intent.params)
            .map_err(|e| ExecutionError {
                code: "PARAM_PARSE_ERROR".to_string(),
                message: format!("Failed to parse parameters: {}", e),
            })?;

        // Resolve path within workdir
        let file_path = ctx.workdir.join(&params.path);
        let canonical_workdir = match fs::canonicalize(&ctx.workdir).await {
            Ok(path) => path,
            Err(_) => ctx.workdir.clone(),
        };

        // Check if path is allowed
        let path_str = file_path.to_string_lossy().to_string();
        if !self.is_path_allowed(&path_str, &ctx.scope.paths) {
            return Err(ExecutionError {
                code: "PATH_DENIED".to_string(),
                message: "File access forbidden due to policy violation".to_string(),
            });
        }

        debug!("Reading file: {:?}", file_path);

        // Track allowlist hit
        let _allowlist_hit = AllowlistHit {
            resource_type: "file".to_string(),
            resource_id: path_str.clone(),
            operation: "read".to_string(),
            timestamp_ns: start_ns,
        };

        // Attempt to read the file
        let read_result = self
            .read_file_safely(
                &canonical_workdir,
                &file_path,
                params.max_bytes,
                params.follow_symlinks,
            )
            .await;

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        match read_result {
            Ok((content, size)) => {
                info!("Successfully read {} bytes from {}", size, params.path);

                let output = json!({
                    "path": params.path,
                    "content": content,
                    "size_bytes": size,
                    "encoding": "utf-8"
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
                        peak_memory_kb: 1024, // Estimate
                        cpu_time_ms: duration_ms as u32,
                        wall_time_ms: duration_ms as u32,
                        fd_count: 1,
                        disk_read_bytes: size,
                        disk_write_bytes: 0,
                        network_tx_bytes: 0,
                        network_rx_bytes: 0,
                    },
                })
            }
            Err(e) => {
                warn!("Failed to read file {}: {}", params.path, e);

                Err(ExecutionError {
                    code: "READ_ERROR".to_string(),
                    message: "File operation failed due to invalid request".to_string(),
                })
            }
        }
    }

    fn describe(&self) -> CapabilitySpec {
        CapabilitySpec {
            name: self.name().to_string(),
            description: "Read file contents from the filesystem with safety controls".to_string(),
            params_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Relative path to the file to read",
                        "example": "config/app.json"
                    },
                    "max_bytes": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10485760,
                        "description": "Maximum bytes to read (default: no limit, max: 10MB)",
                        "example": 1024
                    },
                    "follow_symlinks": {
                        "type": "boolean",
                        "description": "Whether to follow symbolic links (default: true)",
                        "example": false
                    }
                },
                "required": ["path"],
                "additionalProperties": false
            }),
            example_params: json!({
                "path": "README.md",
                "max_bytes": 4096,
                "follow_symlinks": true
            }),
            resource_requirements: ResourceRequirements {
                cpu_ms_typical: 10,
                memory_kb_max: 1024,
                network_access: false,
                filesystem_access: true,
                external_commands: false,
            },
            security_notes: vec![
                "Files must be within the execution workdir".to_string(),
                "Absolute paths and path traversal (..) are forbidden".to_string(),
                "File access is subject to allowlist policy controls".to_string(),
                "Maximum file size is limited to 10MB".to_string(),
            ],
        }
    }
}

impl FsReadV1Capability {
    const MAX_PATH_LENGTH: usize = 512;

    /// Check if a path is allowed according to the execution scope
    fn is_path_allowed(&self, path: &str, allowed_paths: &[String]) -> bool {
        // If no specific paths are configured, allow any path within workdir
        if allowed_paths.is_empty() {
            return true;
        }

        // Check if path matches any allowed pattern
        for allowed in allowed_paths {
            if path.starts_with(allowed) || allowed == "*" {
                return true;
            }
        }

        false
    }

    /// Safely read a file with limits and symlink handling
    async fn read_file_safely(
        &self,
        workdir: &Path,
        path: &Path,
        max_bytes: Option<u64>,
        follow_symlinks: Option<bool>,
    ) -> Result<(String, u64)> {
        // Gather metadata without following symlinks
        let symlink_metadata = fs::symlink_metadata(path)
            .await
            .map_err(|e| anyhow::anyhow!("File does not exist or is inaccessible: {}", e))?;

        let follow = follow_symlinks.unwrap_or(true);
        if symlink_metadata.file_type().is_symlink() && !follow {
            return Err(anyhow::anyhow!(
                "Symbolic links are not allowed without explicitly enabling follow_symlinks"
            ));
        }

        let resolved_path = fs::canonicalize(path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to resolve path: {}", e))?;

        if !resolved_path.starts_with(workdir) {
            return Err(anyhow::anyhow!(
                "Resolved path {} escapes the execution workdir",
                resolved_path.display()
            ));
        }

        // Check if it's a regular file
        let metadata = fs::metadata(&resolved_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get file metadata: {}", e))?;

        if !metadata.is_file() {
            return Err(anyhow::anyhow!("Path is not a regular file"));
        }

        let file_size = metadata.len();

        // Check size limits
        if let Some(max) = max_bytes {
            if file_size > max {
                return Err(anyhow::anyhow!(
                    "File size {} exceeds maximum {}",
                    file_size,
                    max
                ));
            }
        }

        // Read file contents
        let contents = if let Some(max) = max_bytes {
            let mut file = fs::File::open(&resolved_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to open file: {}", e))?;

            let mut buffer = vec![0u8; max as usize];
            let bytes_read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

            buffer.truncate(bytes_read);
            String::from_utf8(buffer)
                .map_err(|e| anyhow::anyhow!("File contains invalid UTF-8: {}", e))?
        } else {
            fs::read_to_string(&resolved_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?
        };

        let size = contents.len() as u64;
        Ok((contents, size))
    }

    fn decoded_path_variants(raw: &str) -> Vec<String> {
        let mut variants = vec![raw.to_string()];
        let mut current = raw.to_string();

        for _ in 0..4 {
            let (decoded, changed) = Self::percent_decode_once(&current);
            if !changed {
                break;
            }

            if !variants.iter().any(|existing| existing == &decoded) {
                variants.push(decoded.clone());
            }
            current = decoded;
        }

        variants
    }

    fn percent_decode_once(input: &str) -> (String, bool) {
        let bytes = input.as_bytes();
        let mut output = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut changed = false;

        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hi = bytes[i + 1];
                let lo = bytes[i + 2];
                if let (Some(hi_val), Some(lo_val)) = (Self::hex_value(hi), Self::hex_value(lo)) {
                    output.push((hi_val << 4) | lo_val);
                    i += 3;
                    changed = true;
                    continue;
                }
            }

            output.push(bytes[i]);
            i += 1;
        }

        if !changed {
            (input.to_string(), false)
        } else {
            let decoded = String::from_utf8_lossy(&output).into_owned();
            (decoded, true)
        }
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    fn path_danger_reason(path: &str) -> Option<&'static str> {
        if path.starts_with('/') || path.starts_with('\\') {
            return Some("Absolute paths are forbidden");
        }

        if Self::contains_windows_drive_prefix(path) {
            return Some("Windows drive prefixes are forbidden");
        }

        let normalized = path.replace('\\', "/");
        let candidate_path = Path::new(&normalized);

        if candidate_path.is_absolute() {
            return Some("Absolute paths are forbidden");
        }

        if candidate_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Some("Path access not allowed due to invalid components");
        }

        None
    }

    fn contains_windows_drive_prefix(path: &str) -> bool {
        let bytes = path.as_bytes();
        if bytes.len() < 2 {
            return false;
        }

        if !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' {
            return false;
        }

        if bytes.len() == 2 {
            return true;
        }

        let next = bytes[2];
        next == b'\\' || next == b'/'
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Capability as ProtoCapability;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn test_fs_read_v1_validation() {
        let capability = FsReadV1Capability::new();

        // Valid intent
        let valid_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({"path": "test.txt"}),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&valid_intent).is_ok());

        // Invalid intent - empty path
        let invalid_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({"path": ""}),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&invalid_intent).is_err());
    }

    #[tokio::test]
    async fn test_fs_read_v1_execution() {
        let capability = FsReadV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, "Hello, World!").await.unwrap();

        // Create execution context
        let ctx = ExecCtx {
            workdir: temp_dir.path().to_path_buf(),
            limits: Default::default(),
            scope: Default::default(),
            trace_id: "test-trace".to_string(),
            sandbox: Default::default(),
        };

        // Create intent
        let intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({"path": "test.txt"}),
            30000,
            "test-signer".to_string(),
        );

        // Execute
        let result = capability.execute(intent, ctx).await;
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.status, ExecutionStatus::Ok);
        assert!(result.output.is_some());

        let output = result.output.unwrap();
        assert_eq!(output["content"], "Hello, World!");
        assert_eq!(output["size_bytes"], 13);
    }

    #[test]
    fn test_path_allowed() {
        let capability = FsReadV1Capability::new();

        // Empty allowlist allows everything
        assert!(capability.is_path_allowed("/any/path", &[]));

        // Specific allowlist
        let allowed = vec!["/allowed".to_string(), "/tmp".to_string()];
        assert!(capability.is_path_allowed("/allowed/file.txt", &allowed));
        assert!(capability.is_path_allowed("/tmp/test", &allowed));
        assert!(!capability.is_path_allowed("/forbidden/file", &allowed));

        // Wildcard allowlist
        let wildcard = vec!["*".to_string()];
        assert!(capability.is_path_allowed("/any/path", &wildcard));
    }

    /// Test path traversal attack vectors - all should be rejected with UNSAFE_PATH
    #[test]
    fn test_validation_path_traversal_attacks() {
        let capability = FsReadV1Capability::new();

        let path_traversal_attacks = vec![
            "../etc/passwd",
            "../../etc/passwd",
            "subdir/../../../etc/passwd",
            "subdir/../../etc/passwd",
            "dir1/dir2/../../../etc/shadow",
            "config/../../../root/.ssh/id_rsa",
            "uploads/../../../etc/hosts",
            // Mixed with valid-looking paths
            "documents/../../../etc/passwd",
            "projects/myapp/../../../etc/shadow",
        ];

        for attack_path in path_traversal_attacks {
            let intent = Intent::new(
                ProtoCapability::FsReadV1,
                "test".to_string(),
                json!({"path": attack_path}),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);
            assert!(
                result.is_err(),
                "Path traversal attack should fail: {}",
                attack_path
            );

            let error = result.unwrap_err();
            assert_eq!(
                error.code, "UNSAFE_PATH",
                "Expected UNSAFE_PATH error for: {}",
                attack_path
            );
            assert!(
                error.message.contains("invalid components"),
                "Error message should mention invalid components for: {}",
                attack_path
            );
        }
    }

    /// Test absolute path attack vectors - all should be rejected with UNSAFE_PATH
    #[test]
    fn test_validation_absolute_path_attacks() {
        let capability = FsReadV1Capability::new();

        let absolute_path_attacks = vec![
            "/etc/passwd",
            "/root/.ssh/id_rsa",
            "/etc/shadow",
            "/proc/version",
            "/sys/class/net",
            "/dev/null",
            "/tmp/sensitive_file",
            "/var/log/auth.log",
            "/home/user/.bashrc",
            "/usr/bin/sudo",
        ];

        for attack_path in absolute_path_attacks {
            let intent = Intent::new(
                ProtoCapability::FsReadV1,
                "test".to_string(),
                json!({"path": attack_path}),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);
            assert!(
                result.is_err(),
                "Absolute path attack should fail: {}",
                attack_path
            );

            let error = result.unwrap_err();
            assert_eq!(
                error.code, "UNSAFE_PATH",
                "Expected UNSAFE_PATH error for: {}",
                attack_path
            );
            assert!(
                error.message.to_lowercase().contains("absolute"),
                "Error message should mention absolute path for: {}, got: {}",
                attack_path,
                error.message
            );
        }
    }

    /// Test size limit violations - all should be rejected with LIMIT_EXCEEDED
    #[test]
    fn test_validation_size_limit_violations() {
        let capability = FsReadV1Capability::new();

        let size_violations = vec![
            10 * 1024 * 1024 + 1, // 10MB + 1 byte
            11 * 1024 * 1024,     // 11MB
            50 * 1024 * 1024,     // 50MB
            100 * 1024 * 1024,    // 100MB
            1024 * 1024 * 1024,   // 1GB
            u64::MAX,             // Maximum possible value
        ];

        for size in size_violations {
            let intent = Intent::new(
                ProtoCapability::FsReadV1,
                "test".to_string(),
                json!({
                    "path": "valid_file.txt",
                    "max_bytes": size
                }),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);
            assert!(
                result.is_err(),
                "Size limit violation should fail: {} bytes",
                size
            );

            let error = result.unwrap_err();
            assert_eq!(
                error.code, "LIMIT_EXCEEDED",
                "Expected LIMIT_EXCEEDED error for: {} bytes",
                size
            );
            assert!(
                error.message.contains("10MB limit"),
                "Error message should mention 10MB limit for: {} bytes",
                size
            );
        }
    }

    /// Test boundary conditions for max_bytes
    #[test]
    fn test_validation_size_limit_boundaries() {
        let capability = FsReadV1Capability::new();

        // Test exactly at the limit (should pass)
        let at_limit_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({
                "path": "valid_file.txt",
                "max_bytes": 10 * 1024 * 1024  // Exactly 10MB
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&at_limit_intent);
        assert!(result.is_ok(), "Exactly 10MB should be allowed");

        // Test just under the limit (should pass)
        let under_limit_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({
                "path": "valid_file.txt",
                "max_bytes": 10 * 1024 * 1024 - 1  // 10MB - 1 byte
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&under_limit_intent);
        assert!(result.is_ok(), "Just under 10MB should be allowed");

        // Test just over the limit (should fail)
        let over_limit_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({
                "path": "valid_file.txt",
                "max_bytes": 10 * 1024 * 1024 + 1  // 10MB + 1 byte
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&over_limit_intent);
        assert!(result.is_err(), "Just over 10MB should be rejected");

        let error = result.unwrap_err();
        assert_eq!(error.code, "LIMIT_EXCEEDED");
    }

    /// Test edge cases and complex path patterns
    #[test]
    fn test_validation_edge_cases() {
        let capability = FsReadV1Capability::new();

        let edge_cases = vec![
            // Complex path traversal patterns
            ("./../../etc/passwd", "UNSAFE_PATH"),
            ("dir/../../../etc/passwd", "UNSAFE_PATH"),
            ("valid/path/../../../../../../etc/passwd", "UNSAFE_PATH"),
            // Mixed separators and patterns (Unix-style)
            ("dir1/../dir2/../../etc/passwd", "UNSAFE_PATH"),
            ("./dir/../../../etc/shadow", "UNSAFE_PATH"),
            // Absolute paths with traversal
            ("/../etc/passwd", "UNSAFE_PATH"),
            ("/tmp/../etc/passwd", "UNSAFE_PATH"),
            // Empty path
            ("", "INVALID_PATH"),
            // Valid paths (should pass)
            ("valid_file.txt", "VALID"),
            ("subdir/file.txt", "VALID"),
            ("deep/nested/path/file.txt", "VALID"),
            ("file-with-dashes.txt", "VALID"),
            ("file_with_underscores.txt", "VALID"),
            ("file.with.dots.txt", "VALID"),
        ];

        for (path, expected_result) in edge_cases {
            let intent = Intent::new(
                ProtoCapability::FsReadV1,
                "test".to_string(),
                json!({"path": path}),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);

            match expected_result {
                "VALID" => {
                    assert!(result.is_ok(), "Valid path should pass: {}", path);
                }
                expected_error => {
                    assert!(result.is_err(), "Invalid path should fail: {}", path);
                    let error = result.unwrap_err();
                    assert_eq!(
                        error.code, expected_error,
                        "Expected error {} for path: {}, got: {}",
                        expected_error, path, error.code
                    );
                }
            }
        }
    }

    /// Test malformed parameters and wrong capability type
    #[test]
    fn test_validation_malformed_parameters() {
        let capability = FsReadV1Capability::new();

        // Wrong capability type
        let wrong_capability_intent = Intent::new(
            ProtoCapability::HttpFetchV1, // Wrong capability type
            "test".to_string(),
            json!({"path": "valid_file.txt"}),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&wrong_capability_intent);
        assert!(result.is_err(), "Wrong capability type should fail");

        let error = result.unwrap_err();
        assert_eq!(error.code, "CAPABILITY_MISMATCH");

        // Missing required path parameter
        let missing_path_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({"max_bytes": 1024}), // Missing path
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&missing_path_intent);
        assert!(result.is_err(), "Missing path parameter should fail");

        let error = result.unwrap_err();
        assert_eq!(error.code, "INVALID_PARAMS");

        // Invalid parameter types
        let invalid_params_intent = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({
                "path": 123,  // Should be string
                "max_bytes": "not_a_number"  // Should be number
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&invalid_params_intent);
        assert!(result.is_err(), "Invalid parameter types should fail");

        let error = result.unwrap_err();
        assert_eq!(error.code, "INVALID_PARAMS");
    }

    /// Test negative max_bytes values are rejected
    #[test]
    fn test_validation_negative_max_bytes() {
        let capability = FsReadV1Capability::new();

        // Test negative max_bytes - should fail during JSON parsing
        let intent_negative_max_bytes = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({
                "path": "test.txt",
                "max_bytes": -1
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent_negative_max_bytes);
        assert!(result.is_err(), "Negative max_bytes should be rejected");

        let error = result.unwrap_err();
        assert_eq!(
            error.code, "INVALID_PARAMS",
            "Expected INVALID_PARAMS error for negative max_bytes"
        );
        assert!(
            error.message.contains("invalid value") && error.message.contains("-1"),
            "Error message should mention the invalid negative value: {}",
            error.message
        );
    }

    /// Test comprehensive negative scenarios for complete coverage
    #[test]
    fn test_validation_comprehensive_negative_scenarios() {
        let capability = FsReadV1Capability::new();

        // Test various forms of path traversal with different depths
        let traversal_depths = vec![
            ("../file.txt", 1),
            ("../../file.txt", 2),
            ("../../../file.txt", 3),
            ("../../../../file.txt", 4),
            ("../../../../../file.txt", 5),
        ];

        for (path, depth) in traversal_depths {
            let intent = Intent::new(
                ProtoCapability::FsReadV1,
                "test".to_string(),
                json!({"path": path}),
                30000,
                "test-signer".to_string(),
            );

            let result = capability.validate(&intent);
            assert!(
                result.is_err(),
                "Path traversal depth {} should fail: {}",
                depth,
                path
            );

            let error = result.unwrap_err();
            assert_eq!(
                error.code, "UNSAFE_PATH",
                "Expected UNSAFE_PATH for depth {}: {}",
                depth, path
            );
        }

        // Test combinations of violations (path traversal + size limit)
        let intent_with_multiple_violations = Intent::new(
            ProtoCapability::FsReadV1,
            "test".to_string(),
            json!({
                "path": "../../../etc/passwd",  // Path traversal violation
                "max_bytes": 100 * 1024 * 1024  // Size limit violation
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent_with_multiple_violations);
        assert!(result.is_err(), "Multiple violations should fail");

        let error = result.unwrap_err();
        // Should fail on first violation encountered (path traversal)
        assert_eq!(
            error.code, "UNSAFE_PATH",
            "Should fail on path traversal first"
        );
    }
}
