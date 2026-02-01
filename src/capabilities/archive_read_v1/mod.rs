//! Archive Read V1 Capability - Modular Implementation
//!
//! Modular implementation of archive reading capability with separated concerns:
//! - format_detection: Archive format detection via magic bytes and extensions
//! - zip_handler: ZIP archive processing with security validation
//! - tar_handler: TAR archive processing (compressed and uncompressed)
//! - security: Path validation and security checks
//! - types: Shared types and configuration structures

pub mod format_detection;
pub mod security;
pub mod tar_handler;
pub mod types;
pub mod zip_handler;

// TODO: Uncomment when archive capability is re-enabled
// pub use format_detection::{ArchiveFormat, FormatDetector};
// pub use zip_handler::ZipHandler;
// pub use tar_handler::TarHandler;
// pub use security::SecurityValidator;
// pub use types::{ArchiveEntry, ArchiveQuotas, ArchiveConfig};
