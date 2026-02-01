//! Integration tests for capability registration and execution
//!
//! Tests the complete capability system including runner registration,
//! intent validation, execution context creation, and result handling.

use anyhow::Result;
use serde_json::json;
use smith_protocol::{Capability as ProtoCapability, ExecutionStatus, Intent, SandboxMode};
use tempfile::TempDir;

use agentd::{
    capabilities::register_builtin_capabilities,
    capability::{
        ExecCtx, ExecutionScope, SandboxConfig,
    },
    runners::{MemoryOutputSink, OutputSink, RunnerRegistry, Scope},
    ExecutionLimits,
};
use smith_protocol::ExecutionLimits as CapabilityExecutionLimits;

/// Test helper to create capability execution context
fn create_capability_exec_context(workdir: std::path::PathBuf) -> ExecCtx {
    ExecCtx {
        workdir,
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: std::collections::HashMap::new(),
        },
        trace_id: "test-trace".to_string(),
        sandbox: SandboxConfig::default(),
    }
}

/// Test that runner registry properly registers all built-in capabilities
#[test]
fn test_runner_registry_initialization() {
    let registry = RunnerRegistry::new(None);

    // Check that currently active runners are registered (fs.write and git.clone are disabled during refactoring)
    let expected_capabilities = vec!["fs.read", "http.fetch", "planner.exec"];

    for capability in &expected_capabilities {
        assert!(
            registry.get_runner(capability).is_some(),
            "Runner for capability '{}' should be registered",
            capability
        );
    }

    let registered_capabilities = registry.capabilities();
    assert!(
        registered_capabilities.len() >= expected_capabilities.len(),
        "Should register at least {} runners",
        expected_capabilities.len()
    );

    for capability in expected_capabilities {
        assert!(
            registered_capabilities.contains(&capability.to_string()),
            "Capability '{}' should be in registered list",
            capability
        );
    }
}

/// Test that capability registry properly registers all built-in capabilities
#[test]
fn test_capability_registry_initialization() {
    let registry = register_builtin_capabilities();

    // Check that currently active capabilities are registered (archive.read.v1 is disabled during refactoring)
    let expected_capabilities = vec![
        "fs.read.v1",
        "http.fetch.v1",
        "sqlite.query.v1",
        "bench.report.v1",
    ];

    for capability in &expected_capabilities {
        assert!(
            registry.get(capability).is_some(),
            "Capability '{}' should be registered",
            capability
        );
    }

    let registered_capabilities = registry.list();
    assert_eq!(
        registered_capabilities.len(),
        expected_capabilities.len(),
        "Should have exactly {} capabilities registered",
        expected_capabilities.len()
    );

    for capability in expected_capabilities {
        assert!(
            registered_capabilities.contains(&capability.to_string()),
            "Capability '{}' should be in registered list",
            capability
        );
    }
}

/// Test runner validation and execution for fs.read capability
#[tokio::test]
async fn test_fs_read_runner_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    tokio::fs::write(&test_file, "Hello, World!").await?;

    let registry = RunnerRegistry::new(None);
    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Test parameter validation - use relative path from working directory
    let file_path = test_file.to_string_lossy().to_string();
    let valid_params = json!({
        "path": file_path.clone(),
        "len": 1024
    });
    runner.validate_params(&valid_params)?;

    // Test execution - put the file path in the scope, not directory
    let exec_context = agentd::runners::create_exec_context(
        temp_dir.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 256 * 1024 * 1024, // 256MB
            io_bytes: 10 * 1024 * 1024,   // 10MB
            pids_max: 5,
            timeout_ms: 15000, // 15 seconds
        },
        Scope {
            paths: vec![file_path.clone()],
            urls: vec![],
        },
        "test-trace-id".to_string(),
    );
    let mut output_sink = MemoryOutputSink::new();

    let result = runner
        .execute(&exec_context, valid_params, &mut output_sink)
        .await?;

    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(result.exit_code.is_some());
    assert_eq!(result.exit_code.unwrap(), 0);
    assert!(result.stdout_bytes > 0);

    // Check that file content was read
    let stdout_content = String::from_utf8_lossy(&output_sink.stdout);
    assert!(stdout_content.contains("Hello, World!"));

    Ok(())
}

/// Test runner validation for invalid parameters
#[tokio::test]
async fn test_fs_read_runner_validation_failure() -> Result<()> {
    let registry = RunnerRegistry::new(None);
    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Test with missing path parameter
    let invalid_params = json!({});
    let validation_result = runner.validate_params(&invalid_params);
    assert!(
        validation_result.is_err(),
        "Should fail validation for missing path"
    );

    // Test with invalid parameter type
    let invalid_params = json!({
        "path": 123
    });
    let validation_result = runner.validate_params(&invalid_params);
    assert!(
        validation_result.is_err(),
        "Should fail validation for invalid path type"
    );

    Ok(())
}

/// Test http.fetch runner integration
#[tokio::test]
async fn test_http_fetch_runner_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);
    let runner = registry
        .get_runner("http.fetch")
        .expect("http.fetch runner should be registered");

    // Test parameter validation (using a localhost URL that might not respond)
    let valid_params = json!({
        "url": "http://127.0.0.1:1234/test",
        "method": "GET",
        "timeout": 1000
    });
    runner.validate_params(&valid_params)?;

    // Test execution (expect failure due to connection refused)
    let exec_context = agentd::runners::create_exec_context(
        temp_dir.path(),
        ExecutionLimits {
            cpu_ms_per_100ms: 80,
            mem_bytes: 256 * 1024 * 1024, // 256MB
            io_bytes: 10 * 1024 * 1024,   // 10MB
            pids_max: 5,
            timeout_ms: 15000, // 15 seconds
        },
        Scope {
            paths: vec![temp_dir.path().to_string_lossy().to_string()],
            urls: vec!["http://127.0.0.1:1234/test".to_string()],
        },
        "test-trace-id".to_string(),
    );
    let mut output_sink = MemoryOutputSink::new();

    let result = runner
        .execute(&exec_context, valid_params, &mut output_sink)
        .await?;

    // Should complete execution even if HTTP request fails
    assert!(matches!(
        result.status,
        ExecutionStatus::Ok | ExecutionStatus::Error
    ));

    Ok(())
}

/// Test capability execution through the new capability system
#[tokio::test]
async fn test_capability_execution_integration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let test_file = temp_dir.path().join("test.txt");
    tokio::fs::write(&test_file, "Capability test content").await?;

    let registry = register_builtin_capabilities();
    let capability = registry
        .get("fs.read.v1")
        .expect("fs.read.v1 capability should be registered");

    // Create test intent with relative path
    let intent = Intent::new(
        ProtoCapability::FsReadV1,
        "test-intent".to_string(),
        json!({
            "path": "test.txt"
        }),
        30000,
        "test-signer".to_string(),
    );

    // Test validation
    capability
        .validate(&intent)
        .map_err(|e| anyhow::anyhow!("Validation failed: {:?}", e))?;

    // Test execution
    let exec_context = create_capability_exec_context(temp_dir.path().to_path_buf());
    let result = capability
        .execute(intent, exec_context)
        .await
        .map_err(|e| anyhow::anyhow!("Execution failed: {:?}", e))?;

    assert_eq!(result.status, ExecutionStatus::Ok);
    assert!(result.output.is_some());

    // Check that file content was read
    let output = result.output.unwrap();
    assert!(output.to_string().contains("Capability test content"));

    Ok(())
}

/// Test capability specification descriptions
#[test]
fn test_capability_specifications() {
    let registry = register_builtin_capabilities();
    let specs = registry.describe_all();

    assert!(!specs.is_empty(), "Should have capability specifications");

    for spec in &specs {
        // Verify all specs have required fields
        assert!(!spec.name.is_empty(), "Capability name should not be empty");
        assert!(
            !spec.description.is_empty(),
            "Capability description should not be empty"
        );
        assert!(
            !spec.security_notes.is_empty(),
            "Security notes should not be empty"
        );

        // Verify resource requirements are reasonable
        assert!(
            spec.resource_requirements.cpu_ms_typical > 0,
            "CPU usage should be positive"
        );
        assert!(
            spec.resource_requirements.memory_kb_max > 0,
            "Memory usage should be positive"
        );
    }

    // Check that specific capabilities have expected properties
    let fs_read_spec = specs.iter().find(|s| s.name == "fs.read.v1");
    assert!(
        fs_read_spec.is_some(),
        "Should have fs.read.v1 specification"
    );
    let fs_read_spec = fs_read_spec.unwrap();
    assert!(
        fs_read_spec.resource_requirements.filesystem_access,
        "fs.read.v1 should require filesystem access"
    );
    assert!(
        !fs_read_spec.resource_requirements.network_access,
        "fs.read.v1 should not require network access"
    );

    let http_fetch_spec = specs.iter().find(|s| s.name == "http.fetch.v1");
    assert!(
        http_fetch_spec.is_some(),
        "Should have http.fetch.v1 specification"
    );
    let http_fetch_spec = http_fetch_spec.unwrap();
    assert!(
        http_fetch_spec.resource_requirements.network_access,
        "http.fetch.v1 should require network access"
    );
}

/// Test runner registry and capability registry coordination
#[test]
fn test_registry_coordination() {
    let runner_registry = RunnerRegistry::new(None);
    let capability_registry = register_builtin_capabilities();

    let runner_capabilities = runner_registry.capabilities();
    let capabilities = capability_registry.list();

    // Both systems should have some registered items
    assert!(
        !runner_capabilities.is_empty(),
        "Runner registry should have registered runners"
    );
    assert!(
        !capabilities.is_empty(),
        "Capability registry should have registered capabilities"
    );

    // Verify that core capabilities exist in both systems (with different naming conventions)
    assert!(
        runner_capabilities.contains(&"fs.read".to_string()),
        "Runner registry should have fs.read"
    );
    assert!(
        capabilities.contains(&"fs.read.v1".to_string()),
        "Capability registry should have fs.read.v1"
    );

    assert!(
        runner_capabilities.contains(&"http.fetch".to_string()),
        "Runner registry should have http.fetch"
    );
    assert!(
        capabilities.contains(&"http.fetch.v1".to_string()),
        "Capability registry should have http.fetch.v1"
    );
}

/// Test intent validation through capability registry
#[test]
fn test_intent_validation_integration() {
    let registry = register_builtin_capabilities();

    // Test valid intent with relative path
    let valid_intent = Intent::new(
        ProtoCapability::FsReadV1,
        "test-intent".to_string(),
        json!({
            "path": "test.txt"
        }),
        30000,
        "test-signer".to_string(),
    );

    let validation_result = registry.validate_intent(&valid_intent);
    assert!(
        validation_result.is_ok(),
        "Valid intent should pass validation"
    );

    // Test intent with invalid capability
    // Note: This would require modifying the intent's capability field directly
    // For this test, we'll test validation through the capability interface

    let fs_read_capability = registry.get("fs.read.v1").unwrap();

    // Test with missing required parameter
    let invalid_params_intent = Intent::new(
        ProtoCapability::FsReadV1,
        "test-intent".to_string(),
        json!({}), // Missing path parameter
        30000,
        "test-signer".to_string(),
    );

    let validation_result = fs_read_capability.validate(&invalid_params_intent);
    assert!(
        validation_result.is_err(),
        "Intent with missing parameters should fail validation"
    );
}

/// Test runner execution with various parameter combinations
#[tokio::test]
async fn test_runner_parameter_variations() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    // Test fs.read with different file types
    let test_files = vec![
        ("text.txt", "Simple text content"),
        ("json.json", r#"{"test": "json content"}"#),
        ("empty.txt", ""),
    ];

    let runner = registry.get_runner("fs.read").unwrap();

    for (filename, content) in test_files {
        let test_file = temp_dir.path().join(filename);
        tokio::fs::write(&test_file, content).await?;

        let params = json!({
            "path": filename,
            "len": 1024
        });

        runner.validate_params(&params)?;

        let exec_context = agentd::runners::create_exec_context(
            temp_dir.path(),
            ExecutionLimits {
                cpu_ms_per_100ms: 80,
                mem_bytes: 256 * 1024 * 1024, // 256MB
                io_bytes: 10 * 1024 * 1024,   // 10MB
                pids_max: 5,
                timeout_ms: 15000, // 15 seconds
            },
            Scope {
                paths: vec![test_file.to_string_lossy().to_string()],
                urls: vec![],
            },
            "test-trace-id".to_string(),
        );
        let mut output_sink = MemoryOutputSink::new();

        let result = runner
            .execute(&exec_context, params, &mut output_sink)
            .await?;

        assert_eq!(
            result.status,
            ExecutionStatus::Ok,
            "Should successfully read {}",
            filename
        );

        if !content.is_empty() {
            assert!(
                result.stdout_bytes > 0,
                "Should have stdout bytes for {}",
                filename
            );
            let stdout_content = String::from_utf8_lossy(&output_sink.stdout);
            assert!(
                stdout_content.contains(content),
                "Should contain expected content for {}",
                filename
            );
        }
    }

    Ok(())
}

/// Test execution context creation and configuration
#[test]
fn test_execution_context_creation() {
    let temp_dir = TempDir::new().unwrap();

    // Test runner execution context creation
    let limits = ExecutionLimits {
        cpu_ms_per_100ms: 80,
        mem_bytes: 256 * 1024 * 1024, // 256MB
        io_bytes: 10 * 1024 * 1024,   // 10MB
        pids_max: 5,
        timeout_ms: 15000, // 15 seconds
    };

    let scope = Scope {
        paths: vec![temp_dir.path().to_string_lossy().to_string()],
        urls: vec!["http://allowed-domain.com".to_string()],
    };

    let exec_context = agentd::runners::create_exec_context(
        temp_dir.path(),
        limits.clone(),
        scope.clone(),
        "test-trace-123".to_string(),
    );

    assert_eq!(exec_context.workdir, temp_dir.path());
    assert_eq!(exec_context.limits.cpu_ms_per_100ms, 80);
    assert_eq!(exec_context.limits.mem_bytes, 256 * 1024 * 1024);
    assert_eq!(exec_context.scope.paths, scope.paths);
    assert_eq!(exec_context.scope.urls, scope.urls);
    assert_eq!(exec_context.trace_id, "test-trace-123");

    // Test capability execution context creation
    let capability_context = create_capability_exec_context(temp_dir.path().to_path_buf());
    assert_eq!(capability_context.workdir, temp_dir.path());
    assert_eq!(capability_context.trace_id, "test-trace");
    assert_eq!(capability_context.sandbox.mode, SandboxMode::Full);
}

/// Test memory output sink functionality
#[test]
fn test_memory_output_sink() -> Result<()> {
    let mut sink = MemoryOutputSink::new();

    // Test stdout writing
    sink.write_stdout(b"stdout line 1\n")?;
    sink.write_stdout(b"stdout line 2\n")?;

    // Test stderr writing
    sink.write_stderr(b"stderr message\n")?;

    // Test log writing
    sink.write_log("INFO", "Information message")?;
    sink.write_log("WARN", "Warning message")?;

    // Verify contents
    let stdout_content = String::from_utf8_lossy(&sink.stdout);
    assert!(stdout_content.contains("stdout line 1"));
    assert!(stdout_content.contains("stdout line 2"));

    let stderr_content = String::from_utf8_lossy(&sink.stderr);
    assert!(stderr_content.contains("stderr message"));

    assert_eq!(sink.logs.len(), 2);
    assert_eq!(sink.logs[0], "[INFO] Information message");
    assert_eq!(sink.logs[1], "[WARN] Warning message");

    Ok(())
}
