//! TAR Archive Handler Module
//!
//! Handles processing of TAR archives (compressed and uncompressed) with security validation.

use anyhow::Result;
use sha2::Digest;
use std::io::Read;
use std::path::Path;
// use tracing::warn;

use super::security::SecurityValidator;
use super::types::{ArchiveEntry, ArchiveQuotas};

/// TAR archive processing handler
pub struct TarHandler;

impl TarHandler {
    /// Process TAR archive (compressed or uncompressed)
    pub fn process_tar(
        path: &Path,
        extract_content: bool,
        compressed: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
    ) -> Result<Vec<ArchiveEntry>> {
        let file = std::fs::File::open(path)?;

        if compressed {
            Self::process_compressed_tar(file, extract_content, quotas, validator)
        } else {
            Self::process_uncompressed_tar(file, extract_content, quotas, validator)
        }
    }

    /// Process gzipped TAR archive
    fn process_compressed_tar(
        file: std::fs::File,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
    ) -> Result<Vec<ArchiveEntry>> {
        let gz_decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(gz_decoder);

        Self::process_tar_entries(archive.entries()?, extract_content, quotas, validator)
    }

    /// Process uncompressed TAR archive
    fn process_uncompressed_tar(
        file: std::fs::File,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
    ) -> Result<Vec<ArchiveEntry>> {
        let mut archive = tar::Archive::new(file);

        Self::process_tar_entries(archive.entries()?, extract_content, quotas, validator)
    }

    /// Process TAR entries with all validations
    fn process_tar_entries<R: Read>(
        entries: tar::Entries<R>,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
    ) -> Result<Vec<ArchiveEntry>> {
        let mut processed_entries = Vec::new();
        let mut total_uncompressed = 0u64;
        let mut entry_count = 0;

        for entry_result in entries {
            entry_count += 1;
            Self::validate_entry_count(entry_count, quotas)?;

            let mut entry = entry_result?;
            let processed_entry = Self::process_single_entry(
                &mut entry,
                extract_content,
                quotas,
                validator,
                &mut total_uncompressed,
            )?;

            processed_entries.push(processed_entry);
        }

        Ok(processed_entries)
    }

    /// Validate entry count doesn't exceed quota
    fn validate_entry_count(count: usize, quotas: &ArchiveQuotas) -> Result<()> {
        if count > quotas.max_entries {
            return Err(anyhow::anyhow!(
                "Archive contains more than {} entries",
                quotas.max_entries
            ));
        }
        Ok(())
    }

    /// Process a single TAR entry
    fn process_single_entry<R: Read>(
        entry: &mut tar::Entry<R>,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
        total_uncompressed: &mut u64,
    ) -> Result<ArchiveEntry> {
        let header = entry.header();
        let entry_path = entry.path()?.to_string_lossy().to_string();
        let size = header.size()?;
        let is_directory = header.entry_type().is_dir();

        // Security validation
        validator.validate_path_safety(&entry_path)?;

        // Size validations
        Self::validate_entry_size(size, quotas, &entry_path)?;
        Self::validate_total_size(size, total_uncompressed, quotas)?;

        // Extract content if requested
        let (content, content_hash) = if extract_content && !is_directory && size > 0 {
            Self::extract_entry_content(entry)?
        } else {
            (None, None)
        };

        Ok(ArchiveEntry {
            path: entry_path,
            size,
            is_directory,
            content,
            content_hash,
        })
    }

    /// Validate individual entry size
    fn validate_entry_size(size: u64, quotas: &ArchiveQuotas, entry_path: &str) -> Result<()> {
        if size > quotas.max_entry_size {
            return Err(anyhow::anyhow!(
                "Entry {} size {} exceeds limit {}",
                entry_path,
                size,
                quotas.max_entry_size
            ));
        }
        Ok(())
    }

    /// Validate total uncompressed size
    fn validate_total_size(
        size: u64,
        total_uncompressed: &mut u64,
        quotas: &ArchiveQuotas,
    ) -> Result<()> {
        *total_uncompressed = total_uncompressed.saturating_add(size);
        if *total_uncompressed > quotas.max_total_size {
            return Err(anyhow::anyhow!(
                "Total uncompressed size {} exceeds limit {}",
                *total_uncompressed,
                quotas.max_total_size
            ));
        }
        Ok(())
    }

    /// Extract content from TAR entry
    fn extract_entry_content<R: Read>(
        entry: &mut tar::Entry<R>,
    ) -> Result<(Option<String>, Option<String>)> {
        let mut buffer = Vec::new();
        entry.read_to_end(&mut buffer)?;

        let content = String::from_utf8(buffer.clone())
            .unwrap_or_else(|_| format!("<binary data {} bytes>", buffer.len()));

        let hash = sha2::Sha256::digest(&buffer);
        let hash_hex = format!("{:x}", hash);

        Ok((Some(content), Some(hash_hex)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_quotas() -> ArchiveQuotas {
        ArchiveQuotas {
            max_entries: 1000,
            max_entry_size: 10 * 1024 * 1024,  // 10MB
            max_total_size: 100 * 1024 * 1024, // 100MB
        }
    }

    #[test]
    fn test_validate_entry_count() {
        let quotas = create_test_quotas();

        // Valid count
        assert!(TarHandler::validate_entry_count(500, &quotas).is_ok());

        // Exceeds limit
        assert!(TarHandler::validate_entry_count(quotas.max_entries + 1, &quotas).is_err());
    }

    #[test]
    fn test_validate_entry_size() {
        let quotas = create_test_quotas();

        // Valid size
        assert!(TarHandler::validate_entry_size(1000, &quotas, "test.txt").is_ok());

        // Exceeds limit
        assert!(
            TarHandler::validate_entry_size(quotas.max_entry_size + 1, &quotas, "large.txt")
                .is_err()
        );
    }

    #[test]
    fn test_validate_total_size() {
        let quotas = create_test_quotas();
        let mut total = 0u64;

        // Valid accumulation
        assert!(TarHandler::validate_total_size(1000, &mut total, &quotas).is_ok());
        assert_eq!(total, 1000);

        // Exceeds total limit
        total = quotas.max_total_size - 500;
        assert!(TarHandler::validate_total_size(1000, &mut total, &quotas).is_err());
    }

    #[test]
    fn test_validate_entry_count_boundary() {
        let quotas = create_test_quotas();

        // At exact limit
        assert!(TarHandler::validate_entry_count(quotas.max_entries, &quotas).is_ok());

        // One over limit
        assert!(TarHandler::validate_entry_count(quotas.max_entries + 1, &quotas).is_err());

        // Zero is valid
        assert!(TarHandler::validate_entry_count(0, &quotas).is_ok());
    }

    #[test]
    fn test_validate_entry_size_boundary() {
        let quotas = create_test_quotas();

        // At exact limit
        assert!(TarHandler::validate_entry_size(quotas.max_entry_size, &quotas, "exact.txt").is_ok());

        // One byte over
        assert!(TarHandler::validate_entry_size(quotas.max_entry_size + 1, &quotas, "over.txt").is_err());

        // Zero size is valid
        assert!(TarHandler::validate_entry_size(0, &quotas, "empty.txt").is_ok());
    }

    #[test]
    fn test_validate_total_size_accumulation() {
        let quotas = create_test_quotas();
        let mut total = 0u64;

        // Accumulate multiple valid entries
        for _ in 0..10 {
            assert!(TarHandler::validate_total_size(1000, &mut total, &quotas).is_ok());
        }
        assert_eq!(total, 10000);
    }

    #[test]
    fn test_validate_total_size_overflow_protection() {
        let quotas = create_test_quotas();
        let mut total = u64::MAX - 100;

        // Should use saturating_add and not overflow
        let result = TarHandler::validate_total_size(1000, &mut total, &quotas);
        assert!(result.is_err()); // Will exceed max_total_size
    }

    #[test]
    fn test_validate_entry_size_error_message() {
        let quotas = create_test_quotas();
        let result = TarHandler::validate_entry_size(quotas.max_entry_size + 1, &quotas, "bigfile.bin");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("bigfile.bin"));
        assert!(err_msg.contains("exceeds limit"));
    }
}
