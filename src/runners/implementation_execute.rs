use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::{debug, info};

use super::{ExecContext, ExecutionResult, OutputSink, Runner};
use smith_protocol::ExecutionStatus;

#[derive(Debug, Deserialize)]
struct FileOperation {
    path: String,
    content: String,
    #[serde(default)]
    mode: OperationMode,
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum OperationMode {
    Overwrite,
    Append,
}

impl Default for OperationMode {
    fn default() -> Self {
        OperationMode::Overwrite
    }
}

pub struct ImplementationExecuteRunner;

impl ImplementationExecuteRunner {
    pub fn new() -> Self {
        Self
    }

    fn validate_operations(value: &Value) -> Result<Vec<FileOperation>> {
        let ops_value = value
            .get("operations")
            .context("Missing 'operations' field for implementation runner")?;
        let operations: Vec<FileOperation> = serde_json::from_value(ops_value.clone())
            .context("Failed to parse 'operations' definitions")?;

        if operations.is_empty() {
            anyhow::bail!("Implementation runner requires at least one operation");
        }

        Ok(operations)
    }

    fn resolve_target_path(workdir: &Path, relative: &str) -> Result<PathBuf> {
        let rel = PathBuf::from(relative);

        if rel.is_absolute() {
            anyhow::bail!("File operation paths must be relative: {}", rel.display());
        }

        for component in rel.components() {
            if matches!(component, Component::ParentDir) {
                anyhow::bail!(
                    "File operation path may not traverse parent directories: {}",
                    rel.display()
                );
            }
        }

        Ok(workdir.join(rel))
    }
}

#[async_trait]
impl Runner for ImplementationExecuteRunner {
    fn digest(&self) -> String {
        "implementation-execute-runner-v1".to_string()
    }

    fn validate_params(&self, params: &Value) -> Result<()> {
        Self::validate_operations(params).map(|_| ())
    }

    async fn execute(
        &self,
        ctx: &ExecContext,
        params: Value,
        out: &mut dyn OutputSink,
    ) -> Result<ExecutionResult> {
        let start = Instant::now();
        let operations = Self::validate_operations(&params)?;

        if let Some(instructions) = params
            .get("instructions")
            .and_then(|value| value.as_str())
            .filter(|s| !s.trim().is_empty())
        {
            out.write_log("INFO", instructions)?;
        }

        let mut summaries = Vec::new();

        for operation in operations {
            let target = Self::resolve_target_path(&ctx.workdir, &operation.path)?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).await.with_context(|| {
                    format!("Failed to create directories for {}", target.display())
                })?;
            }

            match operation.mode {
                OperationMode::Overwrite => {
                    fs::write(&target, operation.content.as_bytes())
                        .await
                        .with_context(|| format!("Failed to write file {}", target.display()))?;
                }
                OperationMode::Append => {
                    let mut file = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&target)
                        .await
                        .with_context(|| {
                            format!("Failed to open file {} for append", target.display())
                        })?;
                    file.write_all(operation.content.as_bytes())
                        .await
                        .with_context(|| {
                            format!("Failed to append to file {}", target.display())
                        })?;
                }
            }

            let summary = format!(
                "{} {} ({} bytes)",
                match operation.mode {
                    OperationMode::Overwrite => "overwrite",
                    OperationMode::Append => "append",
                },
                target
                    .strip_prefix(&ctx.workdir)
                    .unwrap_or(&target)
                    .display(),
                operation.content.len()
            );
            summaries.push(summary);
        }

        let report = summaries.join("\n");
        if !report.is_empty() {
            out.write_stdout(report.as_bytes())?;
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        debug!("implementation runner completed in {}ms", duration_ms);

        Ok(ExecutionResult {
            status: ExecutionStatus::Success,
            exit_code: Some(0),
            artifacts: Vec::new(),
            duration_ms,
            stdout_bytes: report.as_bytes().len() as u64,
            stderr_bytes: 0,
        })
    }
}
