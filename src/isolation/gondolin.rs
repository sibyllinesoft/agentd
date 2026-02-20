//! Gondolin isolation backend
//!
//! This backend provides VM-level isolation via the Gondolin adapter,
//! which manages lightweight virtual machines for command execution.
//! It is the default isolation backend on macOS.
//!
//! Commands are wrapped through the `gondolin exec -- <shell> <args> <command>`
//! interface, delegating sandbox enforcement to the Gondolin VM boundary.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command as TokioCommand;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::core::intent::Command;
use crate::core::isolation::{
    BackendCapabilities, BackendHealth, ExecContext, ExecOutput, IsolationBackend, ResourceLimits,
    ResourceUsage, Sandbox, SandboxCapabilities, SandboxSpec, StreamOutput,
};
use crate::core::sandbox::SandboxId;

/// Configuration for the Gondolin isolation backend.
#[derive(Debug, Clone)]
pub struct GondolinBackendConfig {
    /// Path to the gondolin executable.
    pub command: PathBuf,
    /// Arguments inserted before the shell invocation.
    /// Supports `{session_id}` and `{workdir}` placeholders.
    pub args: Vec<String>,
}

impl Default for GondolinBackendConfig {
    fn default() -> Self {
        Self {
            command: PathBuf::from("gondolin"),
            args: vec!["exec".to_string(), "--".to_string()],
        }
    }
}

/// Gondolin isolation backend.
///
/// Wraps command execution through the Gondolin VM adapter, providing
/// VM-level process and filesystem isolation.
pub struct GondolinBackend {
    work_root: PathBuf,
    config: GondolinBackendConfig,
    sandboxes: RwLock<HashMap<SandboxId, GondolinSandbox>>,
}

impl GondolinBackend {
    pub fn new(work_root: &Path) -> Self {
        Self::with_config(work_root, GondolinBackendConfig::default())
    }

    pub fn with_config(work_root: &Path, config: GondolinBackendConfig) -> Self {
        info!(
            work_root = %work_root.display(),
            gondolin_cmd = %config.command.display(),
            "GondolinBackend initialized"
        );

        Self {
            work_root: work_root.to_path_buf(),
            config,
            sandboxes: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl IsolationBackend for GondolinBackend {
    fn name(&self) -> &str {
        "gondolin"
    }

    async fn probe(&self) -> Result<BackendCapabilities> {
        Ok(BackendCapabilities {
            name: self.name().to_string(),
            filesystem_isolation: true,
            network_isolation: false,
            process_isolation: true,
            resource_limits: false,
            syscall_filtering: false,
            persistent_sandboxes: true,
            snapshots: false,
            max_concurrent_sandboxes: None,
            available_profiles: vec!["gondolin".to_string()],
            platform_features: vec!["vm-isolation".to_string()],
        })
    }

    async fn create_sandbox(&self, spec: &SandboxSpec) -> Result<Box<dyn Sandbox>> {
        let sandbox_id = SandboxId::new();

        let workdir = self.work_root.join(sandbox_id.as_str());
        tokio::fs::create_dir_all(&workdir)
            .await
            .context("Failed to create sandbox workdir")?;

        let capabilities = SandboxCapabilities {
            sandbox_id: sandbox_id.as_str().to_string(),
            backend: self.name().to_string(),
            profile: spec.profile.clone(),
            can_write_filesystem: true,
            readable_paths: spec.allowed_paths_ro.clone(),
            writable_paths: spec.allowed_paths_rw.clone(),
            has_network: true,
            allowed_destinations: vec!["*".to_string()],
            limits: spec.limits.clone(),
            syscall_filter_active: false,
            blocked_syscall_categories: vec![],
            is_persistent: true,
            created_at: chrono::Utc::now(),
            time_remaining_ms: spec.limits.max_wall_time_ms,
        };

        let sandbox = GondolinSandbox {
            id: sandbox_id.clone(),
            workdir,
            spec: spec.clone(),
            capabilities,
            config: self.config.clone(),
            created_at: std::time::Instant::now(),
        };

        {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.insert(sandbox_id, sandbox.clone());
        }

        Ok(Box::new(sandbox))
    }

    async fn list_sandboxes(&self) -> Result<Vec<SandboxId>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes.keys().cloned().collect())
    }

    async fn get_sandbox(&self, id: &SandboxId) -> Result<Option<Box<dyn Sandbox>>> {
        let sandboxes = self.sandboxes.read().await;
        Ok(sandboxes
            .get(id)
            .map(|s| Box::new(s.clone()) as Box<dyn Sandbox>))
    }

    async fn destroy_all(&self) -> Result<()> {
        let sandboxes: Vec<_> = {
            let mut sandboxes = self.sandboxes.write().await;
            sandboxes.drain().collect()
        };

        for (_, sandbox) in sandboxes {
            if let Err(e) = sandbox.destroy().await {
                warn!(sandbox_id = %sandbox.id, error = %e, "Failed to destroy sandbox");
            }
        }

        Ok(())
    }

    async fn health_check(&self) -> Result<BackendHealth> {
        let sandboxes = self.sandboxes.read().await;

        Ok(BackendHealth {
            healthy: true,
            active_sandboxes: sandboxes.len() as u32,
            resource_utilization: 0.0,
            warnings: vec![],
            last_sandbox_created: None,
        })
    }
}

/// A Gondolin-backed sandbox instance.
#[derive(Clone)]
pub struct GondolinSandbox {
    id: SandboxId,
    workdir: PathBuf,
    spec: SandboxSpec,
    capabilities: SandboxCapabilities,
    config: GondolinBackendConfig,
    created_at: std::time::Instant,
}

fn expand_template(template: &str, sandbox_id: &str, workdir: &Path) -> String {
    template
        .replace("{session_id}", sandbox_id)
        .replace("{workdir}", &workdir.display().to_string())
}

#[async_trait]
impl Sandbox for GondolinSandbox {
    fn id(&self) -> &SandboxId {
        &self.id
    }

    fn capabilities(&self) -> &SandboxCapabilities {
        &self.capabilities
    }

    async fn exec(&self, cmd: &Command, ctx: &ExecContext) -> Result<ExecOutput> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<StreamOutput>(100);
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        self.exec_streaming(cmd, ctx, tx).await
    }

    async fn exec_streaming(
        &self,
        cmd: &Command,
        ctx: &ExecContext,
        output_tx: tokio::sync::mpsc::Sender<StreamOutput>,
    ) -> Result<ExecOutput> {
        let start = std::time::Instant::now();

        let workdir = ctx
            .workdir
            .clone()
            .or(cmd.workdir.clone())
            .unwrap_or_else(|| self.workdir.clone());

        // Build the gondolin-wrapped command:
        //   gondolin exec -- <program> <args...>
        let mut process = TokioCommand::new(&self.config.command);
        for arg in &self.config.args {
            process.arg(expand_template(arg, self.id.as_str(), &workdir));
        }
        process.arg(&cmd.program);
        process.args(&cmd.args);

        // Environment
        let mut env: HashMap<String, String> = HashMap::new();
        if cmd.inherit_env {
            env.extend(std::env::vars());
        }
        env.extend(cmd.env.clone());
        env.extend(ctx.extra_env.iter().cloned());
        env.insert(
            "AGENTD_SANDBOX_ID".to_string(),
            self.id.as_str().to_string(),
        );
        env.insert("AGENTD_SANDBOX_MODE".to_string(), "gondolin".to_string());

        process
            .current_dir(&workdir)
            .envs(env)
            .stdin(if cmd.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = process.spawn().context("Failed to spawn gondolin command")?;

        if let Some(stdin_data) = &cmd.stdin {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(stdin_data).await?;
            }
        }

        let timeout = ctx
            .timeout
            .or(cmd.timeout)
            .or(self.spec.limits.max_wall_time_ms.map(Duration::from_millis))
            .unwrap_or(Duration::from_secs(300));

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stdout_tx = output_tx.clone();
        let stderr_tx = output_tx.clone();

        let stdout_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut stdout) = stdout {
                let mut chunk = vec![0u8; 4096];
                loop {
                    match stdout.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = chunk[..n].to_vec();
                            buf.extend_from_slice(&data);
                            let _ = stdout_tx.send(StreamOutput::Stdout(data)).await;
                        }
                        Err(_) => break,
                    }
                }
            }
            buf
        });

        let stderr_handle = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut stderr) = stderr {
                let mut chunk = vec![0u8; 4096];
                loop {
                    match stderr.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            let data = chunk[..n].to_vec();
                            buf.extend_from_slice(&data);
                            let _ = stderr_tx.send(StreamOutput::Stderr(data)).await;
                        }
                        Err(_) => break,
                    }
                }
            }
            buf
        });

        let duration = start.elapsed();

        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                let exit_code = status.code().unwrap_or(-1);
                let stdout_data = stdout_handle.await.unwrap_or_default();
                let stderr_data = stderr_handle.await.unwrap_or_default();
                let duration = start.elapsed();

                let _ = output_tx.send(StreamOutput::Exit { code: exit_code }).await;

                Ok(ExecOutput {
                    exit_code,
                    stdout: stdout_data,
                    stderr: stderr_data,
                    duration,
                    timed_out: false,
                    resource_limited: false,
                    resource_usage: Some(ResourceUsage {
                        peak_memory_bytes: 0,
                        cpu_time_ms: duration.as_millis() as u64,
                        wall_time_ms: duration.as_millis() as u64,
                        bytes_written: 0,
                        bytes_read: 0,
                    }),
                })
            }
            Ok(Err(e)) => Err(e).context("Gondolin process failed"),
            Err(_) => {
                let _ = child.kill().await;
                let _ = output_tx.send(StreamOutput::Exit { code: -1 }).await;

                Ok(ExecOutput {
                    exit_code: -1,
                    stdout: vec![],
                    stderr: b"Gondolin process timed out".to_vec(),
                    duration,
                    timed_out: true,
                    resource_limited: false,
                    resource_usage: None,
                })
            }
        }
    }

    async fn is_alive(&self) -> bool {
        self.workdir.exists()
    }

    async fn suspend(&self) -> Result<()> {
        warn!("Suspend not implemented for Gondolin sandboxes");
        Ok(())
    }

    async fn resume(&self) -> Result<()> {
        warn!("Resume not implemented for Gondolin sandboxes");
        Ok(())
    }

    async fn snapshot(&self, _name: &str) -> Result<String> {
        anyhow::bail!("Snapshots not supported by GondolinBackend")
    }

    async fn restore(&self, _snapshot_id: &str) -> Result<()> {
        anyhow::bail!("Restore not supported by GondolinBackend")
    }

    async fn destroy(&self) -> Result<()> {
        if self.workdir.exists() {
            debug!(
                workdir = %self.workdir.display(),
                "Gondolin sandbox workdir preserved (can be manually removed)"
            );
        }
        Ok(())
    }

    async fn resource_usage(&self) -> Result<ResourceUsage> {
        Ok(ResourceUsage {
            peak_memory_bytes: 0,
            cpu_time_ms: self.created_at.elapsed().as_millis() as u64,
            wall_time_ms: self.created_at.elapsed().as_millis() as u64,
            bytes_written: 0,
            bytes_read: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_spec() -> SandboxSpec {
        SandboxSpec {
            profile: "gondolin".to_string(),
            workdir: PathBuf::from("/workspace"),
            allowed_paths_ro: vec![],
            allowed_paths_rw: vec![],
            bind_mounts: vec![],
            allowed_network: vec![],
            environment: vec![],
            limits: ResourceLimits::default(),
            network_enabled: false,
            seccomp_profile: None,
            creation_timeout: Duration::from_secs(30),
            labels: vec![],
        }
    }

    #[test]
    fn test_gondolin_backend_name() {
        let temp_dir = TempDir::new().unwrap();
        let backend = GondolinBackend::new(temp_dir.path());
        assert_eq!(backend.name(), "gondolin");
    }

    #[tokio::test]
    async fn test_gondolin_probe_reports_vm_isolation() {
        let temp_dir = TempDir::new().unwrap();
        let backend = GondolinBackend::new(temp_dir.path());
        let caps = backend.probe().await.unwrap();

        assert_eq!(caps.name, "gondolin");
        assert!(caps.filesystem_isolation);
        assert!(caps.process_isolation);
        assert!(!caps.syscall_filtering);
    }

    #[tokio::test]
    async fn test_gondolin_create_sandbox() {
        let temp_dir = TempDir::new().unwrap();
        let backend = GondolinBackend::new(temp_dir.path());
        let spec = create_test_spec();

        let sandbox = backend.create_sandbox(&spec).await.unwrap();
        assert_eq!(sandbox.capabilities().backend, "gondolin");
    }

    #[tokio::test]
    async fn test_gondolin_list_sandboxes() {
        let temp_dir = TempDir::new().unwrap();
        let backend = GondolinBackend::new(temp_dir.path());
        let spec = create_test_spec();

        assert_eq!(backend.list_sandboxes().await.unwrap().len(), 0);

        let _ = backend.create_sandbox(&spec).await.unwrap();
        assert_eq!(backend.list_sandboxes().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_gondolin_destroy_all() {
        let temp_dir = TempDir::new().unwrap();
        let backend = GondolinBackend::new(temp_dir.path());
        let spec = create_test_spec();

        let _ = backend.create_sandbox(&spec).await.unwrap();
        let _ = backend.create_sandbox(&spec).await.unwrap();
        assert_eq!(backend.list_sandboxes().await.unwrap().len(), 2);

        backend.destroy_all().await.unwrap();
        assert_eq!(backend.list_sandboxes().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_gondolin_health_check() {
        let temp_dir = TempDir::new().unwrap();
        let backend = GondolinBackend::new(temp_dir.path());

        let health = backend.health_check().await.unwrap();
        assert!(health.healthy);
        assert_eq!(health.active_sandboxes, 0);
    }

    #[test]
    fn test_expand_template() {
        let result = expand_template(
            "--session={session_id} --dir={workdir}",
            "abc-123",
            Path::new("/tmp/work"),
        );
        assert_eq!(result, "--session=abc-123 --dir=/tmp/work");
    }

    #[test]
    fn test_expand_template_no_placeholders() {
        let result = expand_template("exec", "abc-123", Path::new("/tmp"));
        assert_eq!(result, "exec");
    }

    #[test]
    fn test_gondolin_backend_config_default() {
        let config = GondolinBackendConfig::default();
        assert_eq!(config.command, PathBuf::from("gondolin"));
        assert_eq!(config.args, vec!["exec", "--"]);
    }
}
