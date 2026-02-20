//! Non-Linux stub for namespace isolation.
//!
//! On platforms without Linux namespaces (macOS, etc.), these types are
//! available for API compatibility but all enforcement functions return errors.
//! The caller (Jailer) already handles these errors gracefully by continuing
//! with degraded isolation.

use anyhow::Result;
use std::os::unix::io::RawFd;
use tracing::warn;

/// Namespace configuration for sandboxed execution
#[derive(Debug, Clone)]
pub struct NamespaceConfig {
    pub uid_map: Vec<(u32, u32, u32)>,
    pub gid_map: Vec<(u32, u32, u32)>,
    pub mount_proc: bool,
    pub mount_tmpfs: bool,
    pub bind_mounts: Vec<BindMount>,
}

/// Bind mount configuration
#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub readonly: bool,
    pub options: Vec<String>,
}

impl Default for NamespaceConfig {
    fn default() -> Self {
        let host_uid = unsafe { libc::geteuid() as u32 };
        let host_gid = unsafe { libc::getegid() as u32 };
        Self {
            uid_map: vec![(0, host_uid, 1)],
            gid_map: vec![(0, host_gid, 1)],
            mount_proc: false,
            mount_tmpfs: false,
            bind_mounts: Vec::new(),
        }
    }
}

/// Handle to created namespaces
pub struct NamespaceHandle {
    pub pid: libc::pid_t,
    pub user_ns_fd: Option<RawFd>,
    pub mount_ns_fd: Option<RawFd>,
    pub pid_ns_fd: Option<RawFd>,
    pub net_ns_fd: Option<RawFd>,
    pub uts_ns_fd: Option<RawFd>,
    pub ipc_ns_fd: Option<RawFd>,
}

/// Create namespaces for sandboxed execution (stub: always fails)
pub fn create_namespaces(_config: &NamespaceConfig) -> Result<NamespaceHandle> {
    warn!("Linux namespaces are not available on this platform");
    Err(anyhow::anyhow!(
        "Namespace isolation requires Linux; sandboxing will degrade gracefully"
    ))
}

/// Setup mount namespace (stub: always fails)
pub fn setup_mount_namespace(
    _config: &NamespaceConfig,
    _workdir: &std::path::Path,
) -> Result<()> {
    warn!("Mount namespaces are not available on this platform");
    Err(anyhow::anyhow!("Mount namespaces require Linux"))
}

/// Pivot root to workdir (stub: always fails)
pub fn pivot_root_to_workdir(_workdir: &std::path::Path) -> Result<()> {
    warn!("pivot_root is not available on this platform");
    Err(anyhow::anyhow!("pivot_root requires Linux"))
}
