//! File System Write Runner - Modular Implementation
//!
//! Modular implementation of fs.write capability with separated concerns:
//! - permissions: Path validation and actor isolation logic
//! - operations: File writing operations with mode and permission handling
//! - validation: Content parsing and filename validation

use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use smith_protocol::ExecutionStatus;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::debug;

use super::{ExecContext, ExecutionResult, OutputSink, Runner};

pub mod operations;
pub mod permissions;
pub mod validation;

pub use operations::FileWriter;
pub use validation::ContentValidator;

/// File system write runner for fs.write capability
pub struct FsWriteRunner {
    version: String,
}

impl FsWriteRunner {
    /// Create new fs.write runner
    pub fn new() -> Self {
        Self {
            version: "fs-write-v1".to_string(),
        }
    }

    fn scope_path(path: &Path) -> Result<PathBuf> {
        if path.exists() {
            return path
                .canonicalize()
                .map_err(|e| anyhow::anyhow!("Failed to canonicalize {}: {}", path.display(), e));
        }

        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Path has no parent: {}", path.display()))?;
        let filename = path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Path has no filename: {}", path.display()))?;
        let parent = parent.canonicalize().map_err(|e| {
            anyhow::anyhow!("Failed to canonicalize parent {}: {}", parent.display(), e)
        })?;
        Ok(parent.join(filename))
    }

    fn validate_write_path(&self, path: &Path, scope_paths: &[String]) -> Result<PathBuf> {
        let canonical_path = Self::scope_path(path)?;

        for allowed_prefix in scope_paths {
            let allowed = Self::scope_path(Path::new(allowed_prefix))?;
            if canonical_path.starts_with(&allowed) {
                debug!(
                    path = %canonical_path.display(),
                    allowed = %allowed.display(),
                    "fs.write path allowed by scope"
                );
                return Ok(canonical_path);
            }
        }

        Err(anyhow::anyhow!(
            "Path {} is not within any allowed scope prefix",
            canonical_path.display()
        ))
    }

    fn mode_alias(mode: &str) -> &str {
        if mode == "overwrite" {
            "write"
        } else {
            mode
        }
    }

    fn execution_error(
        &self,
        out: &mut dyn OutputSink,
        start_time: Instant,
        code: i32,
        message: &str,
    ) -> Result<ExecutionResult> {
        out.write_log("ERROR", message)?;
        out.write_stderr(message.as_bytes())?;
        Ok(ExecutionResult {
            status: ExecutionStatus::Error,
            exit_code: Some(code),
            artifacts: vec![],
            duration_ms: start_time.elapsed().as_millis().max(1) as u64,
            stdout_bytes: 0,
            stderr_bytes: message.len() as u64,
        })
    }
}

#[async_trait]
impl Runner for FsWriteRunner {
    fn digest(&self) -> String {
        self.version.clone()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        ContentValidator::validate_params(params)
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start_time = Instant::now();
        out.write_log("INFO", "Starting fs.write execution")?;

        if ctx.scope.paths.is_empty() {
            return self.execution_error(
                out,
                start_time,
                1,
                "No allowed scope paths provided for fs.write",
            );
        }

        let path = match params.get("path").and_then(|value| value.as_str()) {
            Some(path) => path,
            None => return self.execution_error(out, start_time, 1, "path parameter is required"),
        };
        let content_value = match params.get("content") {
            Some(content) => content,
            None => {
                return self.execution_error(out, start_time, 1, "content parameter is required");
            }
        };

        let mode = params
            .get("mode")
            .and_then(|value| value.as_str())
            .unwrap_or("write");
        let mode = Self::mode_alias(mode);
        let permissions = params
            .get("permissions")
            .and_then(|value| value.as_str())
            .unwrap_or("644");

        let raw_path = PathBuf::from(if Path::new(path).is_absolute() {
            path.to_string()
        } else {
            ctx.workdir.join(path).to_string_lossy().to_string()
        });

        let canonical_path = match self.validate_write_path(&raw_path, &ctx.scope.paths) {
            Ok(path) => path,
            Err(error) => {
                return self.execution_error(
                    out,
                    start_time,
                    2,
                    &format!("Path validation failed: {}", error),
                );
            }
        };

        let content = match ContentValidator::parse_content(content_value) {
            Ok(content) => content,
            Err(error) => {
                return self.execution_error(
                    out,
                    start_time,
                    3,
                    &format!("Invalid content: {}", error),
                );
            }
        };

        if content.len() as u64 > ctx.limits.io_bytes {
            return self.execution_error(
                out,
                start_time,
                4,
                &format!(
                    "Content size {} exceeds I/O limit {}",
                    content.len(),
                    ctx.limits.io_bytes
                ),
            );
        }

        let parsed_permissions = match FileWriter::parse_permissions(permissions) {
            Ok(value) => value,
            Err(error) => {
                return self.execution_error(
                    out,
                    start_time,
                    5,
                    &format!("Invalid permissions '{}': {}", permissions, error),
                );
            }
        };

        match FileWriter::write_file(&canonical_path, &content, mode, parsed_permissions).await {
            Ok(()) => {
                out.write_log(
                    "INFO",
                    &format!(
                        "Successfully wrote {} bytes to {}",
                        content.len(),
                        canonical_path.display()
                    ),
                )?;
                Ok(ExecutionResult {
                    status: ExecutionStatus::Ok,
                    exit_code: Some(0),
                    artifacts: vec![],
                    duration_ms: start_time.elapsed().as_millis().max(1) as u64,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                })
            }
            Err(error) => self.execution_error(
                out,
                start_time,
                6,
                &format!("Failed to write file: {}", error),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runners::{create_exec_context, MemoryOutputSink, Scope};
    use serde_json::json;
    use smith_protocol::ExecutionLimits;
    use tempfile::tempdir;

    fn test_limits() -> ExecutionLimits {
        ExecutionLimits {
            cpu_ms_per_100ms: 50,
            mem_bytes: 100_000_000,
            io_bytes: 1_048_576,
            pids_max: 10,
            timeout_ms: 30_000,
        }
    }

    #[tokio::test]
    async fn test_runner_digest() {
        let runner = FsWriteRunner::new();
        assert_eq!(runner.digest(), "fs-write-v1");
    }

    #[test]
    fn test_validate_params_allows_overwrite_mode() {
        let runner = FsWriteRunner::new();
        let params = json!({
            "path": "notes.txt",
            "content": "hello",
            "mode": "overwrite",
            "permissions": "644"
        });
        assert!(runner.validate_params(&params).is_ok());
    }

    #[tokio::test]
    async fn test_execute_writes_file_within_scope() {
        let temp_dir = tempdir().unwrap();
        let ctx = create_exec_context(
            temp_dir.path(),
            test_limits(),
            Scope {
                paths: vec![temp_dir.path().to_string_lossy().to_string()],
                urls: vec![],
            },
            "trace-fs-write".to_string(),
        );
        let runner = FsWriteRunner::new();
        let mut out = MemoryOutputSink::new();

        let params = json!({
            "path": "result.txt",
            "content": "written",
            "mode": "overwrite"
        });
        let result = runner.execute(&ctx, params, &mut out).await.unwrap();

        assert_eq!(result.status, ExecutionStatus::Ok);
        let content = std::fs::read_to_string(temp_dir.path().join("result.txt")).unwrap();
        assert_eq!(content, "written");
    }

    #[tokio::test]
    async fn test_execute_rejects_out_of_scope_path() {
        let temp_dir = tempdir().unwrap();
        let outside_dir = tempdir().unwrap();

        let ctx = create_exec_context(
            temp_dir.path(),
            test_limits(),
            Scope {
                paths: vec![temp_dir.path().to_string_lossy().to_string()],
                urls: vec![],
            },
            "trace-fs-write".to_string(),
        );
        let runner = FsWriteRunner::new();
        let mut out = MemoryOutputSink::new();
        let params = json!({
            "path": outside_dir.path().join("forbidden.txt").to_string_lossy().to_string(),
            "content": "nope"
        });

        let result = runner.execute(&ctx, params, &mut out).await.unwrap();
        assert_eq!(result.status, ExecutionStatus::Error);
        assert_eq!(result.exit_code, Some(2));
    }
}
