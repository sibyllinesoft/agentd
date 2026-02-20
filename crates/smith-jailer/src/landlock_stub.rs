//! Non-Linux stub for Landlock filesystem access control.
//!
//! On platforms without Landlock (macOS, etc.), the config types are available
//! for API compatibility. `is_landlock_available()` returns false, which causes
//! the caller to take the fallback path. Real sandboxing on macOS comes from
//! Gondolin (VM-level isolation).

use anyhow::Result;
use smith_config::LandlockProfile;
use std::path::Path;
use tracing::warn;

/// Landlock access rights for filesystem operations
#[repr(u64)]
#[derive(Debug, Clone, Copy)]
pub enum LandlockAccess {
    FsExecute = 1 << 0,
    FsWriteFile = 1 << 1,
    FsReadFile = 1 << 2,
    FsReadDir = 1 << 3,
    FsRemoveDir = 1 << 4,
    FsRemoveFile = 1 << 5,
    FsMakeChar = 1 << 6,
    FsMakeDir = 1 << 7,
    FsMakeReg = 1 << 8,
    FsMakeSock = 1 << 9,
    FsMakeFifo = 1 << 10,
    FsMakeBlock = 1 << 11,
    FsMakeSymlink = 1 << 12,
    FsRefer = 1 << 13,
    FsTruncate = 1 << 14,
}

/// Landlock filesystem rule configuration
#[derive(Debug, Clone)]
pub struct LandlockRule {
    pub path: String,
    pub access_rights: u64,
}

impl LandlockRule {
    /// Create rule allowing only read access
    pub fn read_only(path: &str) -> Self {
        let is_dir = Path::new(path).is_dir();
        let access_rights = if is_dir {
            LandlockAccess::FsReadFile as u64 | LandlockAccess::FsReadDir as u64
        } else {
            LandlockAccess::FsReadFile as u64
        };
        Self {
            path: path.to_string(),
            access_rights,
        }
    }

    /// Create rule allowing read and write access
    pub fn read_write(path: &str) -> Self {
        let is_dir = Path::new(path).is_dir();
        let access_rights = if is_dir {
            LandlockAccess::FsReadFile as u64
                | LandlockAccess::FsReadDir as u64
                | LandlockAccess::FsWriteFile as u64
                | LandlockAccess::FsMakeReg as u64
                | LandlockAccess::FsMakeDir as u64
                | LandlockAccess::FsRemoveFile as u64
                | LandlockAccess::FsRemoveDir as u64
                | LandlockAccess::FsTruncate as u64
        } else {
            LandlockAccess::FsReadFile as u64
                | LandlockAccess::FsWriteFile as u64
                | LandlockAccess::FsTruncate as u64
        };
        Self {
            path: path.to_string(),
            access_rights,
        }
    }

    /// Create rule allowing execution access
    pub fn execute(path: &str) -> Self {
        let is_dir = Path::new(path).is_dir();
        let access_rights = if is_dir {
            LandlockAccess::FsExecute as u64
                | LandlockAccess::FsReadFile as u64
                | LandlockAccess::FsReadDir as u64
        } else {
            LandlockAccess::FsExecute as u64 | LandlockAccess::FsReadFile as u64
        };
        Self {
            path: path.to_string(),
            access_rights,
        }
    }
}

/// Landlock configuration for path-based access control
#[derive(Debug, Clone)]
pub struct LandlockConfig {
    pub enabled: bool,
    pub rules: Vec<LandlockRule>,
    pub default_deny: bool,
}

impl Default for LandlockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules: Vec::new(),
            default_deny: true,
        }
    }
}

impl LandlockConfig {
    /// Add a read-only rule for a path
    pub fn allow_read(&mut self, path: &str) -> &mut Self {
        self.rules.push(LandlockRule::read_only(path));
        self
    }

    /// Add a read-write rule for a path
    pub fn allow_read_write(&mut self, path: &str) -> &mut Self {
        self.rules.push(LandlockRule::read_write(path));
        self
    }

    /// Add an execution rule for a path
    pub fn allow_execute(&mut self, path: &str) -> &mut Self {
        self.rules.push(LandlockRule::execute(path));
        self
    }
}

/// Check if Landlock is available on the system (stub: always false)
pub fn is_landlock_available() -> bool {
    false
}

/// Apply Landlock rules (stub: no-op)
pub fn apply_landlock_rules(_config: &LandlockConfig) -> Result<()> {
    warn!("Landlock is not available on this platform; skipping");
    Ok(())
}

/// Create default Landlock configuration for capability execution (stub: empty config)
pub fn create_capability_landlock_config(
    _capability: &str,
    _allowed_paths: &[String],
    _workdir: &Path,
) -> LandlockConfig {
    LandlockConfig::default()
}

/// Create Landlock configuration from derived policy profiles (stub: empty config)
pub fn landlock_config_from_profile(
    _capability: &str,
    _profile: &LandlockProfile,
    _workdir: &Path,
) -> LandlockConfig {
    LandlockConfig::default()
}

/// Fallback implementation when Landlock is not available (stub: no-op)
pub fn apply_fallback_path_restrictions(_allowed_paths: &[String]) -> Result<()> {
    warn!("Landlock fallback restrictions not applicable on this platform");
    Ok(())
}
