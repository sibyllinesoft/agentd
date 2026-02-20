//! Non-Linux stub for seccomp syscall filtering.
//!
//! On platforms without seccomp (macOS, etc.), the types are available for API
//! compatibility. Enforcement functions are no-ops — on macOS the real
//! sandboxing comes from Gondolin (VM-level isolation).

use anyhow::Result;
use tracing::warn;

/// Seccomp filter actions
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum SeccompAction {
    Kill = 0x00000000,
    Trap = 0x00030000,
    Errno = 0x00050000,
    Allow = 0x7fff0000,
}

/// Seccomp BPF instruction
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Seccomp configuration for capability-specific syscall filtering
#[derive(Debug, Clone)]
pub struct SeccompConfig {
    pub enabled: bool,
    pub default_action: SeccompAction,
    pub allowed_syscalls: Vec<i32>,
}

impl Default for SeccompConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_action: SeccompAction::Kill,
            allowed_syscalls: Vec::new(),
        }
    }
}

impl SeccompConfig {
    /// Add an allowed syscall by number
    pub fn allow_syscall(&mut self, syscall_num: i32) -> &mut Self {
        if !self.allowed_syscalls.contains(&syscall_num) {
            self.allowed_syscalls.push(syscall_num);
        }
        self
    }

    /// Add multiple allowed syscalls
    pub fn allow_syscalls(&mut self, syscalls: &[i32]) -> &mut Self {
        for &syscall in syscalls {
            self.allow_syscall(syscall);
        }
        self
    }
}

/// Create seccomp configuration based on capability (stub: returns empty config)
pub fn create_capability_seccomp_config(_capability: &str) -> SeccompConfig {
    SeccompConfig::default()
}

/// Apply seccomp filter to current process (stub: no-op)
pub fn apply_seccomp_filter(_config: &SeccompConfig) -> Result<()> {
    warn!("Seccomp filtering is not available on this platform; skipping");
    Ok(())
}

/// Generate BPF instructions for seccomp filter (stub: empty)
pub fn generate_bpf_filter(_config: &SeccompConfig) -> Vec<SeccompInstruction> {
    Vec::new()
}

/// Validate that forbidden syscalls are properly blocked (stub: no-op)
pub fn validate_seccomp_blocking() -> Result<()> {
    warn!("Seccomp validation skipped: unsupported platform");
    Ok(())
}

/// Resolve syscall names to numeric identifiers (stub: always None)
pub fn syscall_number_from_name(_name: &str) -> Option<i32> {
    None
}
