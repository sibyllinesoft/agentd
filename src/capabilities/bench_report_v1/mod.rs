use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use smith_protocol::{
    AllowlistHit, CapabilitySpec, ExecutionError, ExecutionStatus, Intent, ResourceRequirements,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

use super::benchmark_statistics::{
    analyze_regression, calculate_statistics, BenchmarkDataPoint, BenchmarkStatistics,
    RegressionAnalysis,
};
use crate::capability::{Artifact, Capability, CapabilityResult, ExecCtx, ExecutionMetadata};

/// BenchReportV1 capability for performance benchmark reporting and tracking
pub struct BenchReportV1Capability {
    /// Default retention period in days
    default_retention_days: u32,
    /// Maximum retention period in days
    max_retention_days: u32,
    /// Benchmark data storage directory (relative to workdir)
    benchmark_dir: String,
}

/// Benchmark summary report
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkReport {
    /// Benchmark name
    pub benchmark_name: String,
    /// Current metrics
    pub current_metrics: HashMap<String, f64>,
    /// Historical data points (limited by retention)
    pub historical_data: Vec<BenchmarkDataPoint>,
    /// Regression analysis
    pub regression_analysis: RegressionAnalysis,
    /// Statistical summary
    pub statistics: BenchmarkStatistics,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
}

impl BenchReportV1Capability {
    pub fn new() -> Self {
        Self {
            default_retention_days: 30,
            max_retention_days: 365, // 1 year max
            benchmark_dir: "benchmarks".to_string(),
        }
    }

    /// Create with custom retention settings
    pub fn with_retention(default_retention_days: u32, max_retention_days: u32) -> Self {
        Self {
            default_retention_days,
            max_retention_days,
            benchmark_dir: "benchmarks".to_string(),
        }
    }

    /// Get the benchmark data file path
    fn get_benchmark_file_path(&self, workdir: &Path, benchmark_name: &str) -> PathBuf {
        workdir
            .join(&self.benchmark_dir)
            .join(format!("{}.json", benchmark_name))
    }

    /// Ensure benchmark directory exists
    async fn ensure_benchmark_dir(&self, workdir: &Path) -> Result<()> {
        let benchmark_dir = workdir.join(&self.benchmark_dir);
        if !benchmark_dir.exists() {
            fs::create_dir_all(&benchmark_dir).await?;
        }
        Ok(())
    }

    /// Load historical benchmark data
    async fn load_historical_data(&self, file_path: &Path) -> Result<Vec<BenchmarkDataPoint>> {
        if !file_path.exists() {
            return Ok(vec![]);
        }

        let content = fs::read_to_string(file_path).await?;
        let data_points: Vec<BenchmarkDataPoint> = serde_json::from_str(&content)?;
        Ok(data_points)
    }

    /// Save benchmark data with retention cleanup
    async fn save_benchmark_data(
        &self,
        file_path: &Path,
        mut data_points: Vec<BenchmarkDataPoint>,
        retention_days: u32,
    ) -> Result<()> {
        // Clean up old data based on retention policy
        let cutoff_date = Utc::now() - Duration::days(retention_days as i64);
        data_points.retain(|point| point.timestamp > cutoff_date);

        // Sort by timestamp (newest first)
        data_points.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Ensure parent directory exists
        if let Some(parent) = file_path.parent() {
            if let Some(workdir) = parent.parent() {
                self.ensure_benchmark_dir(workdir).await?;
            }
        }

        // Save to file
        let json_content = serde_json::to_string_pretty(&data_points)?;
        fs::write(file_path, json_content).await?;

        Ok(())
    }

    /// Generate comprehensive benchmark report
    async fn generate_benchmark_report(
        &self,
        workdir: &Path,
        benchmark_name: &str,
        current_metrics: HashMap<String, f64>,
        metadata: HashMap<String, serde_json::Value>,
        intent_id: String,
        retention_days: u32,
    ) -> Result<BenchmarkReport> {
        self.ensure_benchmark_dir(workdir).await?;
        let file_path = self.get_benchmark_file_path(workdir, benchmark_name);

        // Load historical data
        let mut historical_data = self.load_historical_data(&file_path).await?;

        // Add current data point
        let current_point = BenchmarkDataPoint {
            timestamp: Utc::now(),
            metrics: current_metrics.clone(),
            metadata: metadata.clone(),
            intent_id,
        };

        historical_data.insert(0, current_point);

        // Perform regression analysis
        let regression_analysis = analyze_regression(&current_metrics, &historical_data);

        // Calculate statistics
        let statistics = calculate_statistics(&historical_data);

        // Save updated data with retention cleanup
        self.save_benchmark_data(&file_path, historical_data.clone(), retention_days)
            .await?;

        // Re-load to get cleaned data for report
        let cleaned_historical_data = self.load_historical_data(&file_path).await?;

        Ok(BenchmarkReport {
            benchmark_name: benchmark_name.to_string(),
            current_metrics,
            historical_data: cleaned_historical_data,
            regression_analysis,
            statistics,
            generated_at: Utc::now(),
        })
    }
}

#[async_trait]
impl Capability for BenchReportV1Capability {
    fn name(&self) -> &'static str {
        "bench.report.v1"
    }

    fn validate(&self, intent: &Intent) -> Result<(), ExecutionError> {
        // Validate that this is a bench.report.v1 intent
        if intent.capability != smith_protocol::Capability::BenchReportV1 {
            return Err(ExecutionError {
                code: "CAPABILITY_MISMATCH".to_string(),
                message: format!("Expected bench.report.v1, got {}", intent.capability),
            });
        }

        // Parse and validate parameters
        let params: smith_protocol::params::BenchReportV1 =
            serde_json::from_value(intent.params.clone()).map_err(|e| ExecutionError {
                code: "INVALID_PARAMS".to_string(),
                message: format!("Failed to parse bench.report.v1 parameters: {}", e),
            })?;

        // Validate benchmark name
        if params.benchmark_name.is_empty() {
            return Err(ExecutionError {
                code: "INVALID_BENCHMARK_NAME".to_string(),
                message: "Benchmark name cannot be empty".to_string(),
            });
        }

        // Validate benchmark name format (alphanumeric, underscore, dash only)
        if !params
            .benchmark_name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ExecutionError {
                code: "INVALID_BENCHMARK_NAME_FORMAT".to_string(),
                message: "Benchmark name can only contain alphanumeric characters, underscores, and dashes".to_string(),
            });
        }

        // Validate metrics
        if params.metrics.is_empty() {
            return Err(ExecutionError {
                code: "NO_METRICS".to_string(),
                message: "At least one performance metric must be provided".to_string(),
            });
        }

        // Check for invalid metric values
        for (metric_name, &value) in &params.metrics {
            if !value.is_finite() {
                return Err(ExecutionError {
                    code: "INVALID_METRIC_VALUE".to_string(),
                    message: format!("Metric '{}' has invalid value: {}", metric_name, value),
                });
            }
        }

        // Validate retention days
        if let Some(retention_days) = params.retention_days {
            if retention_days > self.max_retention_days {
                return Err(ExecutionError {
                    code: "RETENTION_EXCEEDED".to_string(),
                    message: format!(
                        "Retention days {} exceeds maximum {}",
                        retention_days, self.max_retention_days
                    ),
                });
            }
        }

        debug!(
            "bench.report.v1 parameters validated successfully for benchmark: {}",
            params.benchmark_name
        );
        Ok(())
    }

    async fn execute(
        &self,
        intent: Intent,
        ctx: ExecCtx,
    ) -> Result<CapabilityResult, ExecutionError> {
        let start_time = std::time::Instant::now();
        let start_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u128;

        info!("Executing bench.report.v1 for intent: {}", intent.id);

        // Parse parameters
        let params: smith_protocol::params::BenchReportV1 = serde_json::from_value(intent.params)
            .map_err(|e| ExecutionError {
            code: "PARAM_PARSE_ERROR".to_string(),
            message: format!("Failed to parse parameters: {}", e),
        })?;

        let retention_days = params.retention_days.unwrap_or(self.default_retention_days);
        let metadata = params.metadata.unwrap_or_default();

        debug!("Generating benchmark report for: {}", params.benchmark_name);

        // Track allowlist hit
        let _allowlist_hit = AllowlistHit {
            resource_type: "benchmark".to_string(),
            resource_id: params.benchmark_name.clone(),
            operation: "report".to_string(),
            timestamp_ns: start_ns,
        };

        // Generate benchmark report
        let report_result = self
            .generate_benchmark_report(
                &ctx.workdir,
                &params.benchmark_name,
                params.metrics.clone(),
                metadata,
                intent.id.clone(),
                retention_days,
            )
            .await;

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        match report_result {
            Ok(report) => {
                info!(
                    "Successfully generated benchmark report for {} with {} historical points",
                    params.benchmark_name,
                    report.historical_data.len()
                );

                // Create artifact for the report
                let report_path =
                    self.get_benchmark_file_path(&ctx.workdir, &params.benchmark_name);
                let report_size = fs::metadata(&report_path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);

                let artifact = Artifact {
                    name: format!("{}_report.json", params.benchmark_name),
                    path: report_path,
                    size: report_size,
                    sha256: "".to_string(), // Could calculate if needed
                };

                let output = json!({
                    "benchmark_name": report.benchmark_name,
                    "current_metrics": report.current_metrics,
                    "historical_count": report.historical_data.len(),
                    "regression_analysis": report.regression_analysis,
                    "statistics": report.statistics,
                    "generated_at": report.generated_at,
                    "retention_days": retention_days,
                    "file_path": format!("{}/{}.json", self.benchmark_dir, params.benchmark_name),
                });

                Ok(CapabilityResult {
                    status: ExecutionStatus::Ok,
                    output: Some(output),
                    error: None,
                    metadata: ExecutionMetadata {
                        pid: std::process::id(),
                        exit_code: Some(0),
                        duration_ms,
                        stdout_bytes: 0,
                        stderr_bytes: 0,
                        artifacts: vec![artifact],
                    },
                    resource_usage: smith_protocol::ResourceUsage {
                        peak_memory_kb: 1024, // Benchmark processing is relatively lightweight
                        cpu_time_ms: duration_ms as u32,
                        wall_time_ms: duration_ms as u32,
                        fd_count: 2, // Read + write benchmark file
                        disk_read_bytes: report_size,
                        disk_write_bytes: report_size,
                        network_tx_bytes: 0,
                        network_rx_bytes: 0,
                    },
                })
            }
            Err(e) => {
                warn!(
                    "Failed to generate benchmark report for {}: {}",
                    params.benchmark_name, e
                );

                Err(ExecutionError {
                    code: "BENCHMARK_REPORT_ERROR".to_string(),
                    message: format!("Failed to generate benchmark report: {}", e),
                })
            }
        }
    }

    fn describe(&self) -> CapabilitySpec {
        CapabilitySpec {
            name: self.name().to_string(),
            description: "Generate performance benchmark reports with historical tracking and regression analysis".to_string(),
            params_schema: json!({
                "type": "object",
                "properties": {
                    "benchmark_name": {
                        "type": "string",
                        "pattern": "^[a-zA-Z0-9_-]+$",
                        "description": "Benchmark identifier (alphanumeric, underscore, dash only)",
                        "example": "api_response_time"
                    },
                    "metrics": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "number"
                        },
                        "description": "Performance metrics as key-value pairs",
                        "example": {
                            "response_time_ms": 125.5,
                            "throughput_rps": 850.2,
                            "memory_usage_mb": 45.3
                        }
                    },
                    "metadata": {
                        "type": "object",
                        "additionalProperties": true,
                        "description": "Additional benchmark metadata (optional)",
                        "example": {
                            "environment": "production",
                            "version": "1.2.3",
                            "load_pattern": "steady_state"
                        }
                    },
                    "retention_days": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 365,
                        "description": "Historical data retention in days (default: 30)",
                        "example": 90
                    }
                },
                "required": ["benchmark_name", "metrics"],
                "additionalProperties": false
            }),
            example_params: json!({
                "benchmark_name": "database_query_performance",
                "metrics": {
                    "avg_query_time_ms": 23.4,
                    "p95_query_time_ms": 45.1,
                    "queries_per_second": 2150.0,
                    "cache_hit_rate": 0.85
                },
                "metadata": {
                    "database_version": "15.2",
                    "dataset_size": "10M_records",
                    "concurrent_users": 100
                },
                "retention_days": 60
            }),
            resource_requirements: ResourceRequirements {
                cpu_ms_typical: 50,
                memory_kb_max: 2048,
                network_access: false,
                filesystem_access: true,
                external_commands: false,
            },
            security_notes: vec![
                "Benchmark data is stored within the execution workdir".to_string(),
                "Historical data is automatically cleaned based on retention policy".to_string(),
                "Benchmark names are restricted to alphanumeric characters for security".to_string(),
                "Regression analysis uses statistical methods to detect performance degradation".to_string(),
                format!("Maximum retention period: {} days", self.max_retention_days),
                "Benchmark files are stored as JSON in the 'benchmarks' subdirectory".to_string(),
                "Performance artifacts are included in execution metadata".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Capability as ProtoCapability;
    use tempfile::TempDir;

    #[test]
    fn test_capability_name() {
        let capability = BenchReportV1Capability::new();
        assert_eq!(capability.name(), "bench.report.v1");
    }

    #[test]
    fn test_capability_describe() {
        let capability = BenchReportV1Capability::new();
        let spec = capability.describe();
        assert_eq!(spec.name, "bench.report.v1");
        assert!(!spec.description.is_empty());
        assert!(spec.resource_requirements.filesystem_access);
        assert!(!spec.resource_requirements.network_access);
        assert!(!spec.security_notes.is_empty());
    }

    #[test]
    fn test_with_retention() {
        let capability = BenchReportV1Capability::with_retention(60, 180);
        assert_eq!(capability.default_retention_days, 60);
        assert_eq!(capability.max_retention_days, 180);
    }

    #[test]
    fn test_get_benchmark_file_path() {
        let capability = BenchReportV1Capability::new();
        let workdir = Path::new("/tmp/test");
        let path = capability.get_benchmark_file_path(workdir, "my_benchmark");
        assert_eq!(
            path,
            PathBuf::from("/tmp/test/benchmarks/my_benchmark.json")
        );
    }

    #[tokio::test]
    async fn test_bench_report_v1_validation() {
        let capability = BenchReportV1Capability::new();

        // Valid intent
        let mut metrics = HashMap::new();
        metrics.insert("response_time".to_string(), 123.5);
        metrics.insert("throughput".to_string(), 850.0);

        let valid_intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "test_benchmark",
                "metrics": metrics
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&valid_intent).is_ok());

        // Invalid intent - empty benchmark name
        let invalid_intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "",
                "metrics": metrics
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&invalid_intent).is_err());
    }

    #[test]
    fn test_validate_capability_mismatch() {
        let capability = BenchReportV1Capability::new();

        // Wrong capability type
        let intent = Intent::new(
            ProtoCapability::FsReadV1, // Wrong capability
            "test".to_string(),
            json!({
                "benchmark_name": "test",
                "metrics": {"test": 1.0}
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "CAPABILITY_MISMATCH");
    }

    #[test]
    fn test_validate_invalid_params() {
        let capability = BenchReportV1Capability::new();

        // Invalid parameters (not an object)
        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!("not an object"),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_PARAMS");
    }

    #[test]
    fn test_validate_no_metrics() {
        let capability = BenchReportV1Capability::new();

        // Empty metrics
        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "test",
                "metrics": {}
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "NO_METRICS");
    }

    #[test]
    fn test_validate_invalid_metric_nan() {
        let capability = BenchReportV1Capability::new();

        // NaN metric value - JSON serialization converts NaN to null, causing parse error
        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "test",
                "metrics": {"test": f64::NAN}
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent);
        assert!(result.is_err());
        // NaN in JSON causes deserialization to fail with INVALID_PARAMS
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_PARAMS");
    }

    #[test]
    fn test_validate_invalid_metric_infinity() {
        let capability = BenchReportV1Capability::new();

        // Infinity metric value - JSON serialization converts Infinity to null, causing parse error
        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "test",
                "metrics": {"test": f64::INFINITY}
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent);
        assert!(result.is_err());
        // Infinity in JSON causes deserialization to fail with INVALID_PARAMS
        let err = result.unwrap_err();
        assert_eq!(err.code, "INVALID_PARAMS");
    }

    #[test]
    fn test_validate_retention_exceeded() {
        let capability = BenchReportV1Capability::new();

        // Retention days exceeds maximum
        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "test",
                "metrics": {"test": 1.0},
                "retention_days": 500 // Exceeds max of 365
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = capability.validate(&intent);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "RETENTION_EXCEEDED");
    }

    #[test]
    fn test_validate_retention_within_limit() {
        let capability = BenchReportV1Capability::new();

        // Retention days within limit
        let intent = Intent::new(
            ProtoCapability::BenchReportV1,
            "test".to_string(),
            json!({
                "benchmark_name": "test",
                "metrics": {"test": 1.0},
                "retention_days": 100
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&intent).is_ok());
    }

    #[test]
    fn test_benchmark_name_validation() {
        let capability = BenchReportV1Capability::new();

        // Valid benchmark names
        let valid_names = vec![
            "simple_benchmark",
            "benchmark-with-dashes",
            "benchmark123",
            "UPPERCASE_BENCHMARK",
            "mixed_Case-123",
        ];

        for name in valid_names {
            let intent = Intent::new(
                ProtoCapability::BenchReportV1,
                "test".to_string(),
                json!({
                    "benchmark_name": name,
                    "metrics": {"test": 1.0}
                }),
                30000,
                "test-signer".to_string(),
            );
            assert!(
                capability.validate(&intent).is_ok(),
                "Failed for name: {}",
                name
            );
        }

        // Invalid benchmark names
        let invalid_names = vec![
            "benchmark with spaces",
            "benchmark/with/slashes",
            "benchmark.with.dots",
            "benchmark@with@special",
            "benchmark#with#hash",
        ];

        for name in invalid_names {
            let intent = Intent::new(
                ProtoCapability::BenchReportV1,
                "test".to_string(),
                json!({
                    "benchmark_name": name,
                    "metrics": {"test": 1.0}
                }),
                30000,
                "test-signer".to_string(),
            );
            assert!(
                capability.validate(&intent).is_err(),
                "Should fail for name: {}",
                name
            );
        }
    }

    #[tokio::test]
    async fn test_regression_analysis() {
        let _capability = BenchReportV1Capability::new();

        // Create historical data points with stable performance
        let mut historical_data = Vec::new();
        for i in 0..10 {
            let mut metrics = HashMap::new();
            metrics.insert("response_time_ms".to_string(), 100.0 + (i as f64 * 2.0)); // Gradually increasing

            historical_data.push(BenchmarkDataPoint {
                timestamp: Utc::now() - Duration::days(i),
                metrics,
                metadata: HashMap::new(),
                intent_id: format!("intent-{}", i),
            });
        }

        // Test with no regression (within normal range)
        let mut current_metrics = HashMap::new();
        current_metrics.insert("response_time_ms".to_string(), 110.0);

        let analysis = analyze_regression(&current_metrics, &historical_data);
        assert!(!analysis.regression_detected);

        // Test with clear regression (significantly higher than historical data)
        current_metrics.insert("response_time_ms".to_string(), 200.0); // Much higher

        let analysis = analyze_regression(&current_metrics, &historical_data);
        assert!(analysis.regression_detected);
        assert!(analysis
            .regressed_metrics
            .contains(&"response_time_ms".to_string()));
    }

    #[tokio::test]
    async fn test_benchmark_file_operations() {
        let capability = BenchReportV1Capability::new();
        let temp_dir = TempDir::new().unwrap();

        let benchmark_name = "test_benchmark";
        let file_path = capability.get_benchmark_file_path(temp_dir.path(), benchmark_name);

        // Test loading non-existent file
        let historical_data = capability.load_historical_data(&file_path).await.unwrap();
        assert!(historical_data.is_empty());

        // Create some test data
        let mut test_data = Vec::new();
        let mut metrics = HashMap::new();
        metrics.insert("test_metric".to_string(), 42.0);

        test_data.push(BenchmarkDataPoint {
            timestamp: Utc::now(),
            metrics,
            metadata: HashMap::new(),
            intent_id: "test-intent".to_string(),
        });

        // Test saving and loading
        capability
            .save_benchmark_data(&file_path, test_data.clone(), 30)
            .await
            .unwrap();
        let loaded_data = capability.load_historical_data(&file_path).await.unwrap();

        assert_eq!(loaded_data.len(), 1);
        assert_eq!(loaded_data[0].intent_id, "test-intent");
        assert_eq!(loaded_data[0].metrics.get("test_metric"), Some(&42.0));
    }
}
