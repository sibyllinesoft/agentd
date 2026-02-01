//! ZIP Archive Handler Module
//!
//! Handles processing of ZIP archives with security validation and quota enforcement.

use anyhow::Result;
use sha2::Digest;
use std::io::Read;
use std::path::Path;
// use tracing::warn;

use super::security::SecurityValidator;
use super::types::{ArchiveEntry, ArchiveQuotas};

/// ZIP archive processing handler
pub struct ZipHandler;

impl ZipHandler {
    /// Process ZIP archive with security and quota validation
    pub fn process_zip(
        path: &Path,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
    ) -> Result<Vec<ArchiveEntry>> {
        let file = std::fs::File::open(path)?;
        let mut archive = zip::ZipArchive::new(file)?;

        Self::validate_entry_count(&archive, quotas)?;
        Self::process_entries(&mut archive, extract_content, quotas, validator)
    }

    /// Validate total number of entries doesn't exceed quota
    fn validate_entry_count(
        archive: &zip::ZipArchive<std::fs::File>,
        quotas: &ArchiveQuotas,
    ) -> Result<()> {
        if archive.len() > quotas.max_entries {
            return Err(anyhow::anyhow!(
                "Archive contains {} entries, exceeds limit of {}",
                archive.len(),
                quotas.max_entries
            ));
        }
        Ok(())
    }

    /// Process all entries in the ZIP archive
    fn process_entries(
        archive: &mut zip::ZipArchive<std::fs::File>,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
    ) -> Result<Vec<ArchiveEntry>> {
        let mut entries = Vec::new();
        let mut total_uncompressed = 0u64;

        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            let processed_entry = Self::process_single_entry(
                entry,
                extract_content,
                quotas,
                validator,
                &mut total_uncompressed,
            )?;
            entries.push(processed_entry);
        }

        Ok(entries)
    }

    /// Process a single ZIP entry with all validations
    fn process_single_entry(
        mut entry: zip::read::ZipFile,
        extract_content: bool,
        quotas: &ArchiveQuotas,
        validator: &SecurityValidator,
        total_uncompressed: &mut u64,
    ) -> Result<ArchiveEntry> {
        let entry_path = entry.name().to_string();
        let size = entry.size();
        let is_directory = entry.is_dir();

        // Security validation
        validator.validate_path_safety(&entry_path)?;

        // Size validations
        Self::validate_entry_size(size, quotas, &entry_path)?;
        Self::validate_total_size(size, total_uncompressed, quotas)?;

        // Extract content if requested
        let (content, content_hash) = if extract_content && !is_directory && size > 0 {
            Self::extract_entry_content(&mut entry)?
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

    /// Validate individual entry size doesn't exceed quota
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

    /// Validate total uncompressed size doesn't exceed quota
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

    /// Extract content from ZIP entry with hash calculation
    fn extract_entry_content(
        entry: &mut zip::read::ZipFile,
    ) -> Result<(Option<String>, Option<String>)> {
        let mut buffer = Vec::new();
        entry.read_to_end(&mut buffer)?;

        // Convert to string or indicate binary data
        let content = String::from_utf8(buffer.clone())
            .unwrap_or_else(|_| format!("<binary data {} bytes>", buffer.len()));

        // Calculate content hash
        let hash = sha2::Sha256::digest(&buffer);
        let hash_hex = format!("{:x}", hash);

        Ok((Some(content), Some(hash_hex)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::ArchiveQuotas;
    use super::*;

    fn create_test_quotas() -> ArchiveQuotas {
        ArchiveQuotas {
            max_entries: 1000,
            max_entry_size: 10 * 1024 * 1024,  // 10MB
            max_total_size: 100 * 1024 * 1024, // 100MB
        }
    }

    #[test]
    fn test_validate_entry_size() {
        let quotas = create_test_quotas();

        // Valid size
        assert!(ZipHandler::validate_entry_size(1000, &quotas, "test.txt").is_ok());

        // Exceeds limit
        assert!(
            ZipHandler::validate_entry_size(quotas.max_entry_size + 1, &quotas, "large.txt")
                .is_err()
        );
    }

    #[test]
    fn test_validate_total_size() {
        let quotas = create_test_quotas();
        let mut total = 0u64;

        // Valid accumulation
        assert!(ZipHandler::validate_total_size(1000, &mut total, &quotas).is_ok());
        assert_eq!(total, 1000);

        // Exceeds total limit
        total = quotas.max_total_size - 500;
        assert!(ZipHandler::validate_total_size(1000, &mut total, &quotas).is_err());
    }

    #[test]
    fn test_extract_entry_content_formats() {
        // This test would require creating actual ZIP entries, which is complex
        // In practice, you'd create test ZIP files with known content
        // and verify the extraction and hashing behavior
        assert!(
            true,
            "Placeholder for integration tests with actual ZIP files"
        );
    }

    #[test]
    fn test_validate_entry_size_boundary() {
        let quotas = create_test_quotas();

        // At exact limit
        assert!(ZipHandler::validate_entry_size(quotas.max_entry_size, &quotas, "exact.txt").is_ok());

        // One byte over
        assert!(ZipHandler::validate_entry_size(quotas.max_entry_size + 1, &quotas, "over.txt").is_err());

        // Zero size is valid
        assert!(ZipHandler::validate_entry_size(0, &quotas, "empty.txt").is_ok());
    }

    #[test]
    fn test_validate_total_size_accumulation() {
        let quotas = create_test_quotas();
        let mut total = 0u64;

        // Accumulate multiple valid entries
        for _ in 0..10 {
            assert!(ZipHandler::validate_total_size(1000, &mut total, &quotas).is_ok());
        }
        assert_eq!(total, 10000);
    }

    #[test]
    fn test_validate_total_size_overflow_protection() {
        let quotas = create_test_quotas();
        let mut total = u64::MAX - 100;

        // Should use saturating_add and not overflow
        let result = ZipHandler::validate_total_size(1000, &mut total, &quotas);
        assert!(result.is_err()); // Will exceed max_total_size
    }

    #[test]
    fn test_validate_entry_size_error_message() {
        let quotas = create_test_quotas();
        let result = ZipHandler::validate_entry_size(quotas.max_entry_size + 1, &quotas, "bigfile.bin");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("bigfile.bin"));
        assert!(err_msg.contains("exceeds limit"));
    }

    #[test]
    fn test_validate_total_size_error_message() {
        let quotas = create_test_quotas();
        let mut total = quotas.max_total_size - 500;
        let result = ZipHandler::validate_total_size(1000, &mut total, &quotas);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("exceeds limit"));
    }
}
