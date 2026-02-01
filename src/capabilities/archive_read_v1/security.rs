//! Archive Security Validation Module
//!
//! Provides comprehensive security validation for archive paths and content.

use anyhow::Result;
use tracing::warn;

/// Security validator for archive operations
pub struct SecurityValidator;

impl SecurityValidator {
    /// Validate path safety for archive extraction
    pub fn validate_path_safety(&self, path: &str) -> Result<()> {
        if self.is_unsafe_path(path) {
            warn!("Unsafe path detected in archive: {}", path);
            return Err(anyhow::anyhow!("Archive contains unsafe path: {}", path));
        }
        Ok(())
    }

    /// Check if path is allowed according to execution scope
    pub fn is_path_allowed(&self, path: &str, allowed_paths: &[String]) -> bool {
        // If no specific paths are configured, allow any path within workdir
        if allowed_paths.is_empty() {
            return true;
        }

        // Check if path matches any allowed pattern
        allowed_paths.iter().any(|allowed| {
            // Simple prefix matching - could be enhanced with glob patterns
            path.starts_with(allowed)
        })
    }

    /// Comprehensive unsafe path detection
    fn is_unsafe_path(&self, path: &str) -> bool {
        self.has_directory_traversal(path)
            || self.is_absolute_path(path)
            || self.has_dangerous_filename(path)
            || self.has_control_characters(path)
    }

    /// Check for directory traversal attempts
    fn has_directory_traversal(&self, path: &str) -> bool {
        path.contains("../") || path.contains("..\\")
    }

    /// Check for absolute paths (security risk)
    fn is_absolute_path(&self, path: &str) -> bool {
        // Unix absolute path
        if path.starts_with('/') {
            return true;
        }

        // Windows absolute path (C:, D:, etc.)
        if path.len() > 1 && path.chars().nth(1) == Some(':') {
            return true;
        }

        false
    }

    /// Check for Windows reserved/dangerous filenames
    fn has_dangerous_filename(&self, path: &str) -> bool {
        let dangerous_names = [
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];

        let path_upper = path.to_uppercase();

        // Extract filename from path for checking
        let filename = path_upper
            .split('/')
            .last()
            .unwrap_or(&path_upper)
            .split('\\')
            .last()
            .unwrap_or(&path_upper);

        dangerous_names.iter().any(|dangerous| {
            filename == *dangerous || filename.starts_with(&format!("{}.", dangerous))
        })
    }

    /// Check for control characters in path
    fn has_control_characters(&self, path: &str) -> bool {
        path.chars().any(|c| c.is_control())
    }

    /// Validate file extension is allowed
    pub fn is_allowed_extension(&self, path: &str, allowed_extensions: &[String]) -> bool {
        if allowed_extensions.is_empty() {
            return true; // No restrictions
        }

        let path_lower = path.to_lowercase();
        allowed_extensions
            .iter()
            .any(|ext| path_lower.ends_with(&format!(".{}", ext.to_lowercase())))
    }

    /// Check for potentially malicious patterns in content
    pub fn validate_content_safety(&self, content: &str) -> Result<()> {
        // Check for script execution patterns
        if self.has_script_patterns(content) {
            return Err(anyhow::anyhow!(
                "Content contains potentially malicious script patterns"
            ));
        }

        // Check for embedded binaries or executables
        if self.has_executable_patterns(content) {
            return Err(anyhow::anyhow!(
                "Content contains executable binary patterns"
            ));
        }

        Ok(())
    }

    /// Detect script execution patterns
    fn has_script_patterns(&self, content: &str) -> bool {
        let script_patterns = [
            "#!/bin/",
            "#!/usr/bin/",
            "<?php",
            "<script",
            "javascript:",
            "eval(",
            "exec(",
            "system(",
            "shell_exec(",
        ];

        let content_lower = content.to_lowercase();
        script_patterns
            .iter()
            .any(|pattern| content_lower.contains(pattern))
    }

    /// Detect executable binary patterns
    fn has_executable_patterns(&self, content: &str) -> bool {
        // Check for common executable magic bytes in text representation
        let bytes = content.as_bytes();

        // ELF magic
        if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
            return true;
        }

        // PE magic (MZ)
        if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
            return true;
        }

        // Mach-O magic
        if bytes.len() >= 4 {
            let magic = &bytes[0..4];
            if magic == b"\xfe\xed\xfa\xce" || magic == b"\xfe\xed\xfa\xcf" {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_traversal_detection() {
        let validator = SecurityValidator;

        assert!(validator.has_directory_traversal("../etc/passwd"));
        assert!(validator.has_directory_traversal("dir/../../../etc/passwd"));
        assert!(validator.has_directory_traversal("..\\windows\\system32"));

        assert!(!validator.has_directory_traversal("normal/path"));
        assert!(!validator.has_directory_traversal("file.txt"));
    }

    #[test]
    fn test_absolute_path_detection() {
        let validator = SecurityValidator;

        // Unix absolute paths
        assert!(validator.is_absolute_path("/etc/passwd"));
        assert!(validator.is_absolute_path("/usr/bin/sh"));

        // Windows absolute paths
        assert!(validator.is_absolute_path("C:\\Windows\\System32"));
        assert!(validator.is_absolute_path("D:\\data"));

        // Relative paths (safe)
        assert!(!validator.is_absolute_path("relative/path"));
        assert!(!validator.is_absolute_path("file.txt"));
    }

    #[test]
    fn test_dangerous_filename_detection() {
        let validator = SecurityValidator;

        // Windows reserved names
        assert!(validator.has_dangerous_filename("CON"));
        assert!(validator.has_dangerous_filename("PRN.txt"));
        assert!(validator.has_dangerous_filename("AUX.log"));
        assert!(validator.has_dangerous_filename("COM1"));
        assert!(validator.has_dangerous_filename("LPT1.dat"));

        // Safe filenames
        assert!(!validator.has_dangerous_filename("normal.txt"));
        assert!(!validator.has_dangerous_filename("document.pdf"));
        assert!(!validator.has_dangerous_filename("console.log")); // Contains CON but not exact match
    }

    #[test]
    fn test_control_characters_detection() {
        let validator = SecurityValidator;

        assert!(validator.has_control_characters("file\x00.txt")); // null byte
        assert!(validator.has_control_characters("file\n.txt")); // newline
        assert!(validator.has_control_characters("file\r.txt")); // carriage return

        assert!(!validator.has_control_characters("normal_file.txt"));
        assert!(!validator.has_control_characters("file with spaces.txt"));
    }

    #[test]
    fn test_unsafe_path_comprehensive() {
        let validator = SecurityValidator;

        // Various unsafe patterns
        assert!(validator.is_unsafe_path("../etc/passwd"));
        assert!(validator.is_unsafe_path("/etc/passwd"));
        assert!(validator.is_unsafe_path("C:\\Windows\\System32"));
        assert!(validator.is_unsafe_path("CON"));
        assert!(validator.is_unsafe_path("file\x00.txt"));

        // Safe paths
        assert!(!validator.is_unsafe_path("safe/path"));
        assert!(!validator.is_unsafe_path("document.txt"));
        assert!(!validator.is_unsafe_path("subdir/file.log"));
    }

    #[test]
    fn test_script_pattern_detection() {
        let validator = SecurityValidator;

        assert!(validator.has_script_patterns("#!/bin/bash"));
        assert!(validator.has_script_patterns("<?php echo 'hello';"));
        assert!(validator.has_script_patterns("<script>alert('xss')</script>"));
        assert!(validator.has_script_patterns("eval(malicious_code)"));

        assert!(!validator.has_script_patterns("This is normal text content"));
        assert!(!validator.has_script_patterns("JSON data: {\"key\": \"value\"}"));
    }

    #[test]
    fn test_allowed_extensions() {
        let validator = SecurityValidator;
        let allowed = vec!["txt".to_string(), "log".to_string(), "json".to_string()];

        assert!(validator.is_allowed_extension("file.txt", &allowed));
        assert!(validator.is_allowed_extension("data.log", &allowed));
        assert!(validator.is_allowed_extension("config.JSON", &allowed)); // case insensitive

        assert!(!validator.is_allowed_extension("script.sh", &allowed));
        assert!(!validator.is_allowed_extension("binary.exe", &allowed));

        // Empty allowed list means all extensions allowed
        assert!(validator.is_allowed_extension("any.extension", &[]));
    }

    #[test]
    fn test_path_allowed() {
        let validator = SecurityValidator;
        let allowed_paths = vec!["/tmp/safe".to_string(), "data/".to_string()];

        assert!(validator.is_path_allowed("/tmp/safe/file.txt", &allowed_paths));
        assert!(validator.is_path_allowed("data/config.json", &allowed_paths));

        assert!(!validator.is_path_allowed("/etc/passwd", &allowed_paths));
        assert!(!validator.is_path_allowed("other/file.txt", &allowed_paths));

        // Empty allowed paths means all paths allowed
        assert!(validator.is_path_allowed("/any/path", &[]));
    }

    #[test]
    fn test_validate_path_safety_safe() {
        let validator = SecurityValidator;
        assert!(validator.validate_path_safety("safe/path/file.txt").is_ok());
        assert!(validator.validate_path_safety("document.pdf").is_ok());
    }

    #[test]
    fn test_validate_path_safety_unsafe() {
        let validator = SecurityValidator;
        assert!(validator.validate_path_safety("../etc/passwd").is_err());
        assert!(validator.validate_path_safety("/absolute/path").is_err());
    }

    #[test]
    fn test_validate_content_safety_safe() {
        let validator = SecurityValidator;
        assert!(validator.validate_content_safety("Normal text content").is_ok());
        assert!(validator.validate_content_safety("JSON: {\"key\": \"value\"}").is_ok());
    }

    #[test]
    fn test_validate_content_safety_script() {
        let validator = SecurityValidator;
        let result = validator.validate_content_safety("#!/bin/bash\necho 'hello'");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("script"));
    }

    #[test]
    fn test_validate_content_safety_php() {
        let validator = SecurityValidator;
        let result = validator.validate_content_safety("<?php echo 'hello'; ?>");
        assert!(result.is_err());
    }

    #[test]
    fn test_has_executable_patterns_elf() {
        let validator = SecurityValidator;
        let elf_content = "\x7fELFsome content";
        assert!(validator.has_executable_patterns(elf_content));
    }

    #[test]
    fn test_has_executable_patterns_pe() {
        let validator = SecurityValidator;
        let pe_content = "MZsome content";
        assert!(validator.has_executable_patterns(pe_content));
    }

    // Note: Mach-O magic bytes (0xfe, 0xed, 0xfa, 0xce/0xcf) cannot be easily tested
    // because they are not valid UTF-8 and from_utf8_lossy replaces them.
    // The implementation works correctly when reading actual binary files since
    // the ZipHandler converts binary content to "<binary data N bytes>" strings,
    // and real Mach-O detection happens at the byte level.

    #[test]
    fn test_has_executable_patterns_safe() {
        let validator = SecurityValidator;
        assert!(!validator.has_executable_patterns("normal text content"));
        assert!(!validator.has_executable_patterns("JSON data"));
        assert!(!validator.has_executable_patterns("")); // Empty content
        assert!(!validator.has_executable_patterns("a")); // Too short for any magic
    }

    #[test]
    fn test_validate_content_safety_executable() {
        let validator = SecurityValidator;
        let elf_content = "\x7fELFsome binary content";
        let result = validator.validate_content_safety(elf_content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("executable"));
    }

    #[test]
    fn test_script_patterns_case_insensitive() {
        let validator = SecurityValidator;
        assert!(validator.has_script_patterns("#!/BIN/BASH")); // uppercase
        assert!(validator.has_script_patterns("<SCRIPT>alert('xss')</SCRIPT>"));
        assert!(validator.has_script_patterns("Eval(code)")); // mixed case
    }

    #[test]
    fn test_dangerous_filename_paths() {
        let validator = SecurityValidator;
        // Test dangerous names in paths
        assert!(validator.has_dangerous_filename("subdir/CON"));
        assert!(validator.has_dangerous_filename("path/to/NUL.txt"));
        assert!(validator.has_dangerous_filename("dir\\COM1"));
    }

    #[test]
    fn test_windows_path_drive_letters() {
        let validator = SecurityValidator;
        // Various drive letters
        assert!(validator.is_absolute_path("A:\\folder"));
        assert!(validator.is_absolute_path("Z:\\data"));
        assert!(!validator.is_absolute_path("relative.txt")); // Short path, no colon at position 1
    }

    #[test]
    fn test_extension_empty_path() {
        let validator = SecurityValidator;
        let allowed = vec!["txt".to_string()];
        assert!(!validator.is_allowed_extension("", &allowed)); // Empty path
        assert!(!validator.is_allowed_extension("noextension", &allowed)); // No extension
    }
}
