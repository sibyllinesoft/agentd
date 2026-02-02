//! Isolation backend implementations
//!
//! This module contains concrete implementations of the `IsolationBackend` trait:
//! - `LinuxNativeBackend`: Uses Landlock LSM for filesystem access control (no mount isolation)
//! - `ContainerBackend`: Uses mount namespaces for true filesystem isolation
//! - `HostDirectBackend`: No isolation, just policy guards (workstation mode)
//!
//! Future implementations:
//! - `MacosNativeBackend`: Uses sandbox-exec (seatbelt)
//! - `VmBackend`: Uses microVMs (firecracker, cloud-hypervisor)

#[cfg(target_os = "linux")]
pub mod container;
pub mod host_direct;
pub mod linux;

#[cfg(target_os = "linux")]
pub use container::ContainerBackend;
pub use host_direct::HostDirectBackend;
pub use linux::LinuxNativeBackend;

use crate::core::isolation::{BackendCapabilities, IsolationBackend};
use std::sync::Arc;

/// Probe the system and return the best available isolation backend
pub async fn detect_best_backend(work_root: &std::path::Path) -> Arc<dyn IsolationBackend> {
    // Try Linux native backend first
    #[cfg(target_os = "linux")]
    {
        match LinuxNativeBackend::new(work_root) {
            Ok(backend) => {
                if let Ok(caps) = backend.probe().await {
                    if caps.is_fully_isolated() {
                        tracing::info!("Using LinuxNativeBackend with full isolation");
                        return Arc::new(backend);
                    } else {
                        tracing::info!("LinuxNativeBackend available with partial isolation");
                        return Arc::new(backend);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("LinuxNativeBackend creation failed: {}", e);
            }
        }
    }

    // Fall back to host-direct mode
    tracing::info!("Using HostDirectBackend (workstation mode)");
    Arc::new(HostDirectBackend::new(work_root))
}

/// Create a backend by name
pub fn create_backend(
    name: &str,
    work_root: &std::path::Path,
) -> anyhow::Result<Arc<dyn IsolationBackend>> {
    match name {
        "linux" | "native" | "linux-native" | "landlock" => {
            #[cfg(target_os = "linux")]
            {
                Ok(Arc::new(LinuxNativeBackend::new(work_root)?))
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("LinuxNativeBackend is only available on Linux")
            }
        }
        "container" | "namespace" | "mount-ns" => {
            #[cfg(target_os = "linux")]
            {
                Ok(Arc::new(ContainerBackend::new(work_root, None)?))
            }
            #[cfg(not(target_os = "linux"))]
            {
                anyhow::bail!("ContainerBackend is only available on Linux")
            }
        }
        "none" | "host" | "host-direct" | "workstation" => {
            Ok(Arc::new(HostDirectBackend::new(work_root)))
        }
        _ => anyhow::bail!("Unknown isolation backend: {}", name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_backend_host_direct() {
        let temp_dir = TempDir::new().unwrap();

        // All host-direct aliases should work
        let aliases = ["none", "host", "host-direct", "workstation"];
        for alias in aliases {
            let backend = create_backend(alias, temp_dir.path());
            assert!(backend.is_ok(), "Failed for alias: {}", alias);
            assert_eq!(backend.unwrap().name(), "host-direct");
        }
    }

    #[test]
    fn test_create_backend_unknown() {
        let temp_dir = TempDir::new().unwrap();
        let result = create_backend("unknown-backend", temp_dir.path());
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("Unknown isolation backend"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_create_backend_linux() {
        let temp_dir = TempDir::new().unwrap();

        let aliases = ["linux", "native", "linux-native"];
        for alias in aliases {
            let result = create_backend(alias, temp_dir.path());
            // On Linux, this should succeed (or fail only due to permissions)
            // We just check it doesn't panic
            let _ = result;
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_create_backend_linux_not_available() {
        let temp_dir = TempDir::new().unwrap();

        let aliases = ["linux", "native", "linux-native"];
        for alias in aliases {
            let result = create_backend(alias, temp_dir.path());
            assert!(result.is_err());
            let err = result.err().unwrap().to_string();
            assert!(err.contains("only available on Linux"));
        }
    }

    #[tokio::test]
    async fn test_detect_best_backend() {
        let temp_dir = TempDir::new().unwrap();
        let backend = detect_best_backend(temp_dir.path()).await;

        // Should return a valid backend
        let name = backend.name();
        assert!(
            name == "host-direct" || name == "linux-native",
            "Unexpected backend: {}",
            name
        );
    }

    #[tokio::test]
    async fn test_backend_probe() {
        let temp_dir = TempDir::new().unwrap();
        let backend = create_backend("host-direct", temp_dir.path()).unwrap();

        let caps = backend.probe().await.unwrap();
        assert_eq!(caps.name, "host-direct");
        // Host-direct has no kernel isolation
        assert!(!caps.filesystem_isolation);
        assert!(!caps.network_isolation);
        assert!(!caps.process_isolation);
        assert!(!caps.syscall_filtering);
        // But supports persistent sandboxes
        assert!(caps.persistent_sandboxes);
    }
}
