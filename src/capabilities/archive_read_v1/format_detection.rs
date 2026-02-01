//! Archive Format Detection Module
//!
//! Handles detection of archive formats based on file extensions and magic bytes.

use anyhow::Result;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::debug;

/// Supported archive formats
#[derive(Debug, Clone, PartialEq)]
pub enum ArchiveFormat {
    Zip,
    TarGz,
    Tar,
}

/// Format detection utilities
pub struct FormatDetector;

impl FormatDetector {
    /// Detect archive format from file path and magic bytes
    pub async fn detect_format(path: &Path) -> Result<ArchiveFormat> {
        let extension = Self::extract_extension(path);
        let magic_bytes = Self::read_magic_bytes(path).await?;

        // Primary detection via magic bytes
        if let Some(format) = Self::detect_by_magic(&magic_bytes) {
            debug!("Detected format by magic bytes: {:?}", format);
            return Ok(format);
        }

        // Fallback to extension-based detection
        Self::detect_by_extension(&extension)
    }

    /// Extract and normalize file extension
    fn extract_extension(path: &Path) -> String {
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase()
    }

    /// Read first 8 bytes for magic byte detection
    async fn read_magic_bytes(path: &Path) -> Result<[u8; 8]> {
        let mut file = fs::File::open(path).await?;
        let mut magic = [0u8; 8];
        file.read_exact(&mut magic).await?;
        Ok(magic)
    }

    /// Detect format by magic bytes (most reliable)
    fn detect_by_magic(magic: &[u8; 8]) -> Option<ArchiveFormat> {
        match magic {
            // ZIP magic: PK\x03\x04 or PK\x05\x06 or PK\x07\x08
            [0x50, 0x4B, 0x03, 0x04, ..]
            | [0x50, 0x4B, 0x05, 0x06, ..]
            | [0x50, 0x4B, 0x07, 0x08, ..] => Some(ArchiveFormat::Zip),

            // Gzip magic: 0x1F 0x8B
            [0x1F, 0x8B, ..] => Some(ArchiveFormat::TarGz),

            // TAR magic is more complex - typically has ustar at offset 257
            _ => None,
        }
    }

    /// Detect format by file extension (fallback)
    fn detect_by_extension(extension: &str) -> Result<ArchiveFormat> {
        match extension {
            "tar" => Ok(ArchiveFormat::Tar),
            "gz" | "tgz" => Ok(ArchiveFormat::TarGz),
            "zip" => Ok(ArchiveFormat::Zip),
            _ => Err(anyhow::anyhow!(
                "Unsupported archive format for extension: {}",
                extension
            )),
        }
    }

    /// Check if format is supported
    pub fn is_supported_extension(extension: &str) -> bool {
        matches!(
            extension.to_lowercase().as_str(),
            "zip" | "tar" | "gz" | "tgz"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_extract_extension() {
        let path = Path::new("test.zip");
        assert_eq!(FormatDetector::extract_extension(path), "zip");

        let path = Path::new("test.tar.gz");
        assert_eq!(FormatDetector::extract_extension(path), "gz");
    }

    #[test]
    fn test_detect_by_magic() {
        // Test ZIP magic
        let zip_magic = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            FormatDetector::detect_by_magic(&zip_magic),
            Some(ArchiveFormat::Zip)
        );

        // Test Gzip magic
        let gzip_magic = [0x1F, 0x8B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            FormatDetector::detect_by_magic(&gzip_magic),
            Some(ArchiveFormat::TarGz)
        );

        // Test unknown magic
        let unknown_magic = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(FormatDetector::detect_by_magic(&unknown_magic), None);
    }

    #[test]
    fn test_detect_by_extension() {
        assert_eq!(
            FormatDetector::detect_by_extension("zip").unwrap(),
            ArchiveFormat::Zip
        );
        assert_eq!(
            FormatDetector::detect_by_extension("tar").unwrap(),
            ArchiveFormat::Tar
        );
        assert_eq!(
            FormatDetector::detect_by_extension("gz").unwrap(),
            ArchiveFormat::TarGz
        );
        assert_eq!(
            FormatDetector::detect_by_extension("tgz").unwrap(),
            ArchiveFormat::TarGz
        );

        assert!(FormatDetector::detect_by_extension("unknown").is_err());
    }

    #[test]
    fn test_is_supported_extension() {
        assert!(FormatDetector::is_supported_extension("zip"));
        assert!(FormatDetector::is_supported_extension("tar"));
        assert!(FormatDetector::is_supported_extension("gz"));
        assert!(FormatDetector::is_supported_extension("tgz"));

        assert!(!FormatDetector::is_supported_extension("rar"));
        assert!(!FormatDetector::is_supported_extension("7z"));
    }

    #[tokio::test]
    async fn test_detect_format_with_zip_file() {
        // Create a temporary file with ZIP magic bytes
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(&[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00])
            .unwrap();

        let format = FormatDetector::detect_format(temp_file.path())
            .await
            .unwrap();
        assert_eq!(format, ArchiveFormat::Zip);
    }
}
