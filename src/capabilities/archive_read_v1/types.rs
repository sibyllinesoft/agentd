//! Archive Processing Types Module
//!
//! Contains shared types and structures used across archive processing modules.

/// Archive entry information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArchiveEntry {
    /// Entry path within archive
    pub path: String,
    /// Entry size in bytes
    pub size: u64,
    /// Whether entry is a directory
    pub is_directory: bool,
    /// Entry content (for files, optional based on extract_content flag)
    pub content: Option<String>,
    /// Content hash if content was extracted
    pub content_hash: Option<String>,
}

/// Archive processing quotas and limits
#[derive(Debug, Clone)]
pub struct ArchiveQuotas {
    /// Maximum number of entries to extract (default 1000)
    pub max_entries: usize,
    /// Maximum uncompressed size per entry (default 10MB)
    pub max_entry_size: u64,
    /// Maximum total uncompressed size (default 500MB)
    pub max_total_size: u64,
}

impl ArchiveQuotas {
    /// Create default quotas
    pub fn default() -> Self {
        Self {
            max_entries: 1000,
            max_entry_size: 10 * 1024 * 1024,  // 10MB
            max_total_size: 500 * 1024 * 1024, // 500MB
        }
    }

    /// Create custom quotas
    pub fn new(max_entries: usize, max_entry_size: u64, max_total_size: u64) -> Self {
        Self {
            max_entries,
            max_entry_size,
            max_total_size,
        }
    }

    /// Validate quota values are reasonable
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.max_entries == 0 {
            return Err(anyhow::anyhow!("max_entries must be greater than 0"));
        }

        if self.max_entry_size == 0 {
            return Err(anyhow::anyhow!("max_entry_size must be greater than 0"));
        }

        if self.max_total_size == 0 {
            return Err(anyhow::anyhow!("max_total_size must be greater than 0"));
        }

        if self.max_entry_size > self.max_total_size {
            return Err(anyhow::anyhow!(
                "max_entry_size cannot exceed max_total_size"
            ));
        }

        // Reasonable upper limits to prevent abuse
        const MAX_ENTRIES_LIMIT: usize = 100_000;
        const MAX_SIZE_LIMIT: u64 = 10 * 1024 * 1024 * 1024; // 10GB

        if self.max_entries > MAX_ENTRIES_LIMIT {
            return Err(anyhow::anyhow!(
                "max_entries exceeds reasonable limit of {}",
                MAX_ENTRIES_LIMIT
            ));
        }

        if self.max_entry_size > MAX_SIZE_LIMIT {
            return Err(anyhow::anyhow!(
                "max_entry_size exceeds reasonable limit of {} bytes",
                MAX_SIZE_LIMIT
            ));
        }

        if self.max_total_size > MAX_SIZE_LIMIT {
            return Err(anyhow::anyhow!(
                "max_total_size exceeds reasonable limit of {} bytes",
                MAX_SIZE_LIMIT
            ));
        }

        Ok(())
    }
}

/// Archive processing configuration
#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    /// Security quotas
    pub quotas: ArchiveQuotas,
    /// Whether to extract file content
    pub extract_content: bool,
    /// Allowed file extensions (empty means all allowed)
    pub allowed_extensions: Vec<String>,
    /// Maximum archive file size
    pub max_archive_size: u64,
}

impl ArchiveConfig {
    /// Create default configuration
    pub fn default() -> Self {
        Self {
            quotas: ArchiveQuotas::default(),
            extract_content: true,
            allowed_extensions: Vec::new(),
            max_archive_size: 100 * 1024 * 1024, // 100MB
        }
    }

    /// Create custom configuration
    pub fn new(
        quotas: ArchiveQuotas,
        extract_content: bool,
        allowed_extensions: Vec<String>,
        max_archive_size: u64,
    ) -> Self {
        Self {
            quotas,
            extract_content,
            allowed_extensions,
            max_archive_size,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        self.quotas.validate()?;

        if self.max_archive_size == 0 {
            return Err(anyhow::anyhow!("max_archive_size must be greater than 0"));
        }

        // Validate allowed extensions don't contain dangerous patterns
        for ext in &self.allowed_extensions {
            if ext.contains("..") || ext.contains("/") || ext.contains("\\") {
                return Err(anyhow::anyhow!("Invalid extension pattern: {}", ext));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_quotas_default() {
        let quotas = ArchiveQuotas::default();
        assert_eq!(quotas.max_entries, 1000);
        assert_eq!(quotas.max_entry_size, 10 * 1024 * 1024);
        assert_eq!(quotas.max_total_size, 500 * 1024 * 1024);
        assert!(quotas.validate().is_ok());
    }

    #[test]
    fn test_archive_quotas_validation() {
        // Valid quotas
        let quotas = ArchiveQuotas::new(100, 1024, 10240);
        assert!(quotas.validate().is_ok());

        // Invalid: max_entries = 0
        let quotas = ArchiveQuotas::new(0, 1024, 10240);
        assert!(quotas.validate().is_err());

        // Invalid: max_entry_size > max_total_size
        let quotas = ArchiveQuotas::new(100, 10240, 1024);
        assert!(quotas.validate().is_err());

        // Invalid: unreasonable limits
        let quotas = ArchiveQuotas::new(1_000_000, 1024, 10240);
        assert!(quotas.validate().is_err());
    }

    #[test]
    fn test_archive_config_default() {
        let config = ArchiveConfig::default();
        assert!(config.extract_content);
        assert!(config.allowed_extensions.is_empty());
        assert_eq!(config.max_archive_size, 100 * 1024 * 1024);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_archive_config_validation() {
        // Valid config
        let config = ArchiveConfig::new(
            ArchiveQuotas::default(),
            true,
            vec!["txt".to_string(), "json".to_string()],
            1024 * 1024,
        );
        assert!(config.validate().is_ok());

        // Invalid: max_archive_size = 0
        let config = ArchiveConfig::new(ArchiveQuotas::default(), true, vec![], 0);
        assert!(config.validate().is_err());

        // Invalid: dangerous extension pattern
        let config = ArchiveConfig::new(
            ArchiveQuotas::default(),
            true,
            vec!["../exe".to_string()],
            1024 * 1024,
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_archive_entry_creation() {
        let entry = ArchiveEntry {
            path: "test/file.txt".to_string(),
            size: 1024,
            is_directory: false,
            content: Some("Hello, World!".to_string()),
            content_hash: Some("hash123".to_string()),
        };

        assert_eq!(entry.path, "test/file.txt");
        assert_eq!(entry.size, 1024);
        assert!(!entry.is_directory);
        assert_eq!(entry.content.as_ref().unwrap(), "Hello, World!");
        assert_eq!(entry.content_hash.as_ref().unwrap(), "hash123");
    }
}
