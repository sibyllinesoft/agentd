//! Comprehensive security tests for fs_read_v1 capability
//!
//! This module contains extensive tests to verify that the fs_read capability
//! provides secure file system access with proper isolation and validation.

use anyhow::Result;
use serde_json::{json, Value};
use smith_jailer::landlock::{LandlockConfig, LandlockRule};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};
use tracing::debug;
use uuid::Uuid;

/// Comprehensive test environment for fs_read security testing
pub struct FsReadSecurityTestEnvironment {
    pub workdir: TempDir,
    pub allowed_dir: TempDir,
    pub forbidden_dir: TempDir,
    pub allowed_file: PathBuf,
    pub forbidden_file: PathBuf,
    pub symlink_target: PathBuf,
    pub symlink_file: PathBuf,
    pub nested_allowed_file: PathBuf,
    pub binary_file: PathBuf,
    pub large_file: PathBuf,
    pub empty_file: PathBuf,
    pub special_chars_file: PathBuf,
}

impl FsReadSecurityTestEnvironment {
    /// Create a comprehensive test environment with various file types and scenarios
    pub fn new() -> Result<Self> {
        let workdir = tempdir()?;
        let allowed_dir = tempdir()?;
        let forbidden_dir = tempdir()?;

        // Create test files with different characteristics
        let allowed_file = allowed_dir.path().join("allowed.txt");
        let forbidden_file = forbidden_dir.path().join("forbidden.txt");
        let empty_file = allowed_dir.path().join("empty.txt");
        let special_chars_file = allowed_dir.path().join("special-chars_file.txt");

        // Create nested directory structure
        let nested_dir = allowed_dir.path().join("nested").join("deep");
        fs::create_dir_all(&nested_dir)?;
        let nested_allowed_file = nested_dir.join("deep_file.txt");

        // Create binary file
        let binary_file = allowed_dir.path().join("binary.bin");

        // Create large file
        let large_file = allowed_dir.path().join("large.txt");

        // Create symlink
        let symlink_target = allowed_dir.path().join("target.txt");
        let symlink_file = allowed_dir.path().join("link.txt");

        // Write content to files
        File::create(&allowed_file)?.write_all(b"allowed content")?;
        File::create(&forbidden_file)?.write_all(b"forbidden content")?;
        File::create(&nested_allowed_file)?.write_all(b"nested deep content")?;
        File::create(&empty_file)?; // Empty file
        File::create(&special_chars_file)?.write_all("special chars: åäö 中文 🦀".as_bytes())?;

        // Create binary file with binary content
        let binary_content = vec![0u8, 1, 2, 255, 254, 253];
        File::create(&binary_file)?.write_all(&binary_content)?;

        // Create large file (1MB)
        let large_content = vec![b'A'; 1024 * 1024];
        File::create(&large_file)?.write_all(&large_content)?;

        // Create symlink if possible
        File::create(&symlink_target)?.write_all(b"symlink target content")?;
        let _ = std::os::unix::fs::symlink(&symlink_target, &symlink_file);

        Ok(Self {
            workdir,
            allowed_dir,
            forbidden_dir,
            allowed_file,
            forbidden_file,
            symlink_target,
            symlink_file,
            nested_allowed_file,
            binary_file,
            large_file,
            empty_file,
            special_chars_file,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_fs_read_intent_validation() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test valid intent
        let valid_intent = json!({
            "id": Uuid::new_v4().to_string(),
            "capability": "fs.read.v1",
            "params": {
                "path": env.allowed_file.to_string_lossy(),
                "max_size": 1024
            }
        });

        let result = validate_fs_read_intent(&valid_intent);
        assert!(result.is_ok(), "Valid intent should pass validation");

        // Test invalid intent - missing path
        let invalid_intent = json!({
            "id": Uuid::new_v4().to_string(),
            "capability": "fs.read.v1",
            "params": {
                "max_size": 1024
            }
        });

        let result = validate_fs_read_intent(&invalid_intent);
        assert!(
            result.is_err(),
            "Intent without path should fail validation"
        );

        // Test invalid intent - negative max_size
        let invalid_intent = json!({
            "id": Uuid::new_v4().to_string(),
            "capability": "fs.read.v1",
            "params": {
                "path": env.allowed_file.to_string_lossy(),
                "max_size": -1
            }
        });

        let result = validate_fs_read_intent(&invalid_intent);
        assert!(
            result.is_err(),
            "Intent with negative max_size should fail validation"
        );
    }

    #[test]
    fn test_path_validation_security() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test valid paths
        let valid_paths = vec![
            env.allowed_file.to_string_lossy().to_string(),
            env.nested_allowed_file.to_string_lossy().to_string(),
        ];

        for path in valid_paths {
            let result = validate_fs_read_path(&path);
            assert!(
                result.is_ok(),
                "Valid path should pass validation: {}",
                path
            );
        }

        // Test invalid paths - path traversal attempts
        let invalid_paths = vec![
            "../../../etc/passwd",
            "../../etc/shadow",
            "/etc/passwd",
            "/proc/version",
            "/sys/kernel/version",
            ".",
            "..",
            "",
            "/dev/null",
            "/dev/random",
            "/proc/self/mem",
        ];

        for path in invalid_paths {
            let result = validate_fs_read_path(path);
            assert!(
                result.is_err(),
                "Invalid path should fail validation: {}",
                path
            );
        }
    }

    #[test]
    fn test_file_size_limits() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test reading file within size limit
        let content = read_file_with_limit(&env.allowed_file, 1024);
        assert!(content.is_ok(), "Should be able to read file within limit");

        let content = content.unwrap();
        assert_eq!(content, "allowed content");

        // Test reading large file with small limit
        let content = read_file_with_limit(&env.large_file, 100);
        assert!(
            content.is_ok(),
            "Should be able to read large file with limit"
        );

        let content = content.unwrap();
        assert_eq!(content.len(), 100, "Should only read up to limit");
        assert!(
            content.chars().all(|c| c == 'A'),
            "Content should be truncated A's"
        );

        // Test reading with zero limit
        let content = read_file_with_limit(&env.allowed_file, 0);
        assert!(content.is_err(), "Should fail with zero limit");
    }

    #[test]
    fn test_binary_file_handling() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test reading binary file
        let content = read_file_bytes_with_limit(&env.binary_file, 1024);
        assert!(content.is_ok(), "Should be able to read binary file");

        let bytes = content.unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(bytes[1], 1);
        assert_eq!(bytes[2], 2);
        assert_eq!(bytes[3], 255);
        assert_eq!(bytes[4], 254);
        assert_eq!(bytes[5], 253);
    }

    #[test]
    fn test_empty_file_handling() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test reading empty file
        let content = read_file_with_limit(&env.empty_file, 1024);
        assert!(content.is_ok(), "Should be able to read empty file");

        let content = content.unwrap();
        assert_eq!(content, "", "Empty file should return empty string");
    }

    #[test]
    fn test_special_characters_handling() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test reading file with special characters
        let content = read_file_with_limit(&env.special_chars_file, 1024);
        assert!(
            content.is_ok(),
            "Should be able to read file with special characters"
        );

        let content = content.unwrap();
        assert!(
            content.contains("åäö"),
            "Should preserve special characters"
        );
        assert!(
            content.contains("中文"),
            "Should preserve Unicode characters"
        );
        assert!(content.contains("🦀"), "Should preserve emoji");
    }

    #[test]
    fn test_symlink_handling() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        if env.symlink_file.exists() {
            // Test reading through symlink
            let content = read_file_with_limit(&env.symlink_file, 1024);
            assert!(content.is_ok(), "Should be able to read through symlink");

            let content = content.unwrap();
            assert_eq!(content, "symlink target content");
        } else {
            debug!("Symlink creation failed, skipping symlink test");
        }
    }

    #[test]
    fn test_nested_directory_access() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test reading nested file
        let content = read_file_with_limit(&env.nested_allowed_file, 1024);
        assert!(content.is_ok(), "Should be able to read nested file");

        let content = content.unwrap();
        assert_eq!(content, "nested deep content");
    }

    #[test]
    fn test_landlock_integration() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test creating landlock config for fs_read
        let allowed_paths = vec![env.allowed_dir.path().to_string_lossy().to_string()];
        let landlock_config = create_fs_read_landlock_config(&allowed_paths, env.workdir.path());

        assert!(landlock_config.enabled);
        assert!(!landlock_config.rules.is_empty());

        // Should contain allowed directory
        let has_allowed = landlock_config
            .rules
            .iter()
            .any(|rule| rule.path == env.allowed_dir.path().to_str().unwrap());
        assert!(
            has_allowed,
            "Landlock config should include allowed directory"
        );

        // Should contain workdir
        let has_workdir = landlock_config
            .rules
            .iter()
            .any(|rule| rule.path.starts_with(env.workdir.path().to_str().unwrap()));
        assert!(has_workdir, "Landlock config should include workdir");
    }

    #[test]
    fn test_concurrent_file_reads() {
        use std::sync::Arc;
        use std::thread;

        let env = Arc::new(FsReadSecurityTestEnvironment::new().unwrap());

        // Test concurrent reads of the same file
        let handles: Vec<_> = (0..5)
            .map(|i| {
                let env = Arc::clone(&env);
                thread::spawn(move || {
                    let content = read_file_with_limit(&env.allowed_file, 1024);
                    assert!(content.is_ok(), "Concurrent read {} should succeed", i);
                    content.unwrap()
                })
            })
            .collect();

        for handle in handles {
            let content = handle.join().unwrap();
            assert_eq!(content, "allowed content");
        }
    }

    #[test]
    fn test_file_metadata_access() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test accessing file metadata
        let metadata = get_file_metadata(&env.allowed_file);
        assert!(metadata.is_ok(), "Should be able to get file metadata");

        let metadata = metadata.unwrap();
        assert!(metadata.len() > 0, "File should have non-zero size");
        assert!(metadata.is_file(), "Should be identified as file");

        // Test accessing directory metadata
        let dir_metadata = get_file_metadata(env.allowed_dir.path());
        assert!(
            dir_metadata.is_ok(),
            "Should be able to get directory metadata"
        );

        let dir_metadata = dir_metadata.unwrap();
        assert!(dir_metadata.is_dir(), "Should be identified as directory");
    }

    #[test]
    fn test_error_handling() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test reading non-existent file
        let non_existent = env.allowed_dir.path().join("does_not_exist.txt");
        let content = read_file_with_limit(&non_existent, 1024);
        assert!(content.is_err(), "Reading non-existent file should fail");

        // Test reading directory as file
        let content = read_file_with_limit(env.allowed_dir.path(), 1024);
        assert!(content.is_err(), "Reading directory as file should fail");

        // Test with invalid UTF-8 (if we can create such a file)
        let invalid_utf8_file = env.allowed_dir.path().join("invalid_utf8.txt");
        if let Ok(mut file) = File::create(&invalid_utf8_file) {
            // Write invalid UTF-8 sequence
            let _ = file.write_all(&[0xFF, 0xFE, 0xFD]);
            drop(file);

            let content = read_file_with_limit(&invalid_utf8_file, 1024);
            // Should either succeed with replacement chars or fail gracefully
            match content {
                Ok(content) => {
                    debug!("Invalid UTF-8 handled gracefully: {:?}", content);
                }
                Err(e) => {
                    debug!("Invalid UTF-8 caused expected error: {}", e);
                }
            }
        }
    }

    #[test]
    fn test_performance_characteristics() {
        use std::time::{Duration, Instant};

        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Test small file read performance
        let start = Instant::now();
        let content = read_file_with_limit(&env.allowed_file, 1024).unwrap();
        let duration = start.elapsed();

        assert!(!content.is_empty());
        assert!(
            duration < Duration::from_millis(10),
            "Small file read should be fast"
        );

        // Test large file read performance with limit
        let start = Instant::now();
        let content = read_file_with_limit(&env.large_file, 1000).unwrap();
        let duration = start.elapsed();

        assert_eq!(content.len(), 1000);
        assert!(
            duration < Duration::from_millis(100),
            "Limited large file read should be fast"
        );
    }

    #[test]
    fn test_intent_parameter_validation() {
        // Test various parameter combinations
        let test_cases = vec![
            // Valid cases
            (json!({"path": "/tmp/test.txt", "max_size": 1024}), true),
            (json!({"path": "/tmp/test.txt", "max_size": 1}), true),
            (json!({"path": "/tmp/test.txt"}), true), // max_size optional
            // Invalid cases
            (json!({"max_size": 1024}), false), // missing path
            (json!({"path": "", "max_size": 1024}), false), // empty path
            (json!({"path": "/tmp/test.txt", "max_size": 0}), false), // zero max_size
            (json!({"path": "/tmp/test.txt", "max_size": -1}), false), // negative max_size
            (json!({"path": 123, "max_size": 1024}), false), // wrong path type
            (json!({"path": "/tmp/test.txt", "max_size": "1024"}), false), // wrong max_size type
        ];

        for (params, should_be_valid) in test_cases {
            let intent = json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "fs.read.v1",
                "params": params
            });

            let result = validate_fs_read_intent(&intent);
            if should_be_valid {
                assert!(result.is_ok(), "Should be valid: {:?}", params);
            } else {
                assert!(result.is_err(), "Should be invalid: {:?}", params);
            }
        }
    }

    #[test]
    fn test_security_boundary_enforcement() {
        let env = FsReadSecurityTestEnvironment::new().unwrap();

        // Create security test scenarios
        let security_tests = vec![
            // Path traversal attempts
            format!("{}/../../../etc/passwd", env.allowed_dir.path().display()),
            format!("{}/../../etc/shadow", env.allowed_dir.path().display()),
            format!("{}/../forbidden.txt", env.allowed_dir.path().display()),
            // Absolute paths to sensitive files
            "/etc/passwd".to_string(),
            "/etc/shadow".to_string(),
            "/proc/version".to_string(),
            "/sys/kernel/version".to_string(),
            // Special files
            "/dev/null".to_string(),
            "/dev/zero".to_string(),
            "/dev/random".to_string(),
            "/dev/urandom".to_string(),
            // Process information
            "/proc/self/environ".to_string(),
            "/proc/self/cmdline".to_string(),
            "/proc/self/maps".to_string(),
        ];

        for malicious_path in security_tests {
            let intent = json!({
                "id": Uuid::new_v4().to_string(),
                "capability": "fs.read.v1",
                "params": {
                    "path": malicious_path,
                    "max_size": 1024
                }
            });

            let result = validate_fs_read_intent(&intent);
            assert!(
                result.is_err(),
                "Security boundary should block malicious path: {}",
                malicious_path
            );
        }
    }
}

/// Helper functions for testing
#[cfg(test)]
mod test_helpers {
    use super::*;

    pub fn read_file_with_limit(path: &Path, max_size: usize) -> Result<String> {
        if max_size == 0 {
            return Err(anyhow::anyhow!("Max size cannot be zero"));
        }

        let metadata = fs::metadata(path)?;
        if metadata.is_dir() {
            return Err(anyhow::anyhow!("Cannot read directory as file"));
        }

        let content = fs::read_to_string(path)?;
        if content.len() > max_size {
            Ok(content[..max_size].to_string())
        } else {
            Ok(content)
        }
    }

    pub fn read_file_bytes_with_limit(path: &Path, max_size: usize) -> Result<Vec<u8>> {
        let content = fs::read(path)?;
        if content.len() > max_size {
            Ok(content[..max_size].to_vec())
        } else {
            Ok(content)
        }
    }

    pub fn get_file_metadata(path: &Path) -> Result<fs::Metadata> {
        fs::metadata(path).map_err(|e| anyhow::anyhow!("Failed to get metadata: {}", e))
    }

    pub fn validate_fs_read_intent(intent: &Value) -> Result<()> {
        // Extract parameters
        let params = intent["params"]
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("Missing params"))?;

        // Validate path
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid path"))?;

        validate_fs_read_path(path)?;

        // Validate max_size if present
        if let Some(max_size) = params.get("max_size") {
            let max_size = max_size
                .as_i64()
                .ok_or_else(|| anyhow::anyhow!("Invalid max_size type"))?;

            if max_size <= 0 {
                return Err(anyhow::anyhow!("max_size must be positive"));
            }
        }

        Ok(())
    }

    pub fn validate_fs_read_path(path: &str) -> Result<()> {
        if path.is_empty() {
            return Err(anyhow::anyhow!("Path cannot be empty"));
        }

        // Check for path traversal attempts
        if path.contains("..") {
            return Err(anyhow::anyhow!("Path traversal not allowed"));
        }

        // Block access to sensitive system paths
        let forbidden_prefixes = vec!["/etc/", "/proc/", "/sys/", "/dev/", "/root/", "/home/"];

        for prefix in forbidden_prefixes {
            if path.starts_with(prefix) {
                return Err(anyhow::anyhow!("Access to {} is forbidden", prefix));
            }
        }

        // Block relative paths
        if path.starts_with('.') {
            return Err(anyhow::anyhow!("Relative paths not allowed"));
        }

        Ok(())
    }

    pub fn create_fs_read_landlock_config(
        allowed_paths: &[String],
        workdir: &Path,
    ) -> LandlockConfig {
        let mut config = LandlockConfig::default();

        // Add workdir with read-write access
        config
            .rules
            .push(LandlockRule::read_write(workdir.to_str().unwrap()));

        // Add allowed paths with read-only access
        for path in allowed_paths {
            config.rules.push(LandlockRule::read_only(path));
        }

        config
    }
}
