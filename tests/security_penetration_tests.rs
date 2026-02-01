//! Security Penetration Tests for Smith Executor
//!
//! Advanced security tests that attempt to exploit the sandbox
//! and verify that all security layers hold under attack.

use anyhow::Result;
use serde_json::json;
use std::{collections::HashMap, path::PathBuf};
use tempfile::TempDir;

use agentd::{
    capabilities::register_builtin_capabilities,
    capability::{
        ExecCtx, ExecutionScope, SandboxConfig,
    },
    runners::{create_exec_context, MemoryOutputSink, RunnerRegistry, Scope},
    ExecutionLimits,
};
use smith_protocol::ExecutionLimits as CapabilityExecutionLimits;
use smith_protocol::{Capability as ProtoCapability, Intent, SandboxMode};

/// Test filesystem isolation bypass attempts
#[tokio::test]
async fn test_filesystem_isolation_penetration() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("fs.read.v1")
        .expect("fs.read.v1 should be registered");

    // Create legitimate file in working directory
    let allowed_file = temp_dir.path().join("allowed.txt");
    tokio::fs::write(&allowed_file, "This file is allowed").await?;

    // Attempt various path traversal attacks
    let traversal_attacks = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "C:\\Windows\\System32\\config\\SAM",
        "allowed.txt/../../../etc/passwd",
        "allowed.txt/../../../../../../proc/version",
        "./../../../../etc/hosts",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", // URL encoded
        "..%252f..%252f..%252fetc%252fpasswd",     // Double URL encoded
        "..%5c..%5c..%5cetc%5cpasswd",             // URL encoded backslash
        "allowed.txt\0../../../../etc/passwd",     // Null byte injection
    ];

    let exec_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "penetration-test".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    for (i, attack_path) in traversal_attacks.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::FsReadV1,
            format!("attack-{}", i),
            json!({ "path": attack_path }),
            30000,
            "attacker".to_string(),
        );

        // All path traversal attempts should be blocked during validation
        let validation_result = capability.validate(&intent);
        assert!(
            validation_result.is_err(),
            "Path traversal attack should be blocked: {}",
            attack_path
        );

        // Even if validation somehow passed, execution should fail safely
        if validation_result.is_ok() {
            let execution_result = capability.execute(intent, exec_context.clone()).await;
            assert!(
                execution_result.is_err()
                    || execution_result.unwrap().status == smith_protocol::ExecutionStatus::Error,
                "Execution should fail safely for attack: {}",
                attack_path
            );
        }
    }

    // Verify legitimate access still works
    let legitimate_intent = Intent::new(
        ProtoCapability::FsReadV1,
        "legitimate".to_string(),
        json!({ "path": "allowed.txt" }),
        30000,
        "user".to_string(),
    );

    assert!(
        capability.validate(&legitimate_intent).is_ok(),
        "Legitimate file access should still work"
    );

    Ok(())
}

/// Test HTTP fetch security bypass attempts
#[tokio::test]
async fn test_http_fetch_penetration() -> Result<()> {
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("http.fetch.v1")
        .expect("http.fetch.v1 should be registered");

    // Attempt various network bypass attacks
    let network_attacks = vec![
        "http://127.0.0.1:22",                                 // SSH port
        "http://localhost:3306",                               // MySQL port
        "http://192.168.1.1/admin",                            // Private network
        "http://10.0.0.1/config",                              // Private network
        "http://172.16.0.1/setup",                             // Private network
        "http://169.254.169.254/metadata",                     // AWS metadata service
        "http://metadata.google.internal/computeMetadata/v1/", // GCP metadata
        "ftp://private-server.internal/secrets",               // Non-HTTP scheme
        "file:///etc/passwd",                                  // Local file access
        "javascript:alert('xss')",                             // JavaScript scheme
        "data:text/plain;base64,ZXRjL3Bhc3N3ZA==",             // Data URL
        "http://[::1]:22",                                     // IPv6 localhost
        "http://0x7f000001",                                   // Hex notation localhost
        "http://2130706433",                                   // Decimal notation localhost
        "http://0177.0.0.1",                                   // Octal notation localhost
        "http://127.1",                                        // Shortened IP notation
        "http://example.com@127.0.0.1/",                       // Username trick
        "http://127.0.0.1#.example.com/",                      // Fragment trick
        "http://127.0.0.1.example.com/", // Subdomain trick (if resolved to localhost)
    ];

    for (i, attack_url) in network_attacks.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::HttpFetchV1,
            format!("network-attack-{}", i),
            json!({
                "url": attack_url,
                "method": "GET"
            }),
            30000,
            "attacker".to_string(),
        );

        // All network bypass attempts should be blocked during validation
        let validation_result = capability.validate(&intent);
        assert!(
            validation_result.is_err(),
            "Network bypass attack should be blocked: {}",
            attack_url
        );
    }

    // Test legitimate external URL
    let legitimate_intent = Intent::new(
        ProtoCapability::HttpFetchV1,
        "legitimate".to_string(),
        json!({
            "url": "https://httpbin.org/get",
            "method": "GET"
        }),
        30000,
        "user".to_string(),
    );

    assert!(
        capability.validate(&legitimate_intent).is_ok(),
        "Legitimate external URL should be allowed"
    );

    Ok(())
}

/// Test resource exhaustion attacks
#[tokio::test]
async fn test_resource_exhaustion_protection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = RunnerRegistry::new(None);

    let runner = registry
        .get_runner("fs.read")
        .expect("fs.read runner should be registered");

    // Create a large file for exhaustion testing
    let large_file = temp_dir.path().join("large.txt");
    let content = "A".repeat(10 * 1024 * 1024); // 10MB
    tokio::fs::write(&large_file, &content).await?;

    // Test with very restrictive resource limits
    let restrictive_limits = ExecutionLimits {
        cpu_ms_per_100ms: 10,   // Very restrictive
        mem_bytes: 1024 * 1024, // 1MB only
        io_bytes: 512 * 1024,   // 512KB I/O limit
        pids_max: 1,
        timeout_ms: 2000, // 2 second timeout
    };

    let exec_context = create_exec_context(
        temp_dir.path(),
        restrictive_limits.clone(),
        Scope {
            paths: vec![large_file.to_string_lossy().to_string()],
            urls: vec![],
        },
        "exhaustion-test".to_string(),
    );

    let mut output_sink = MemoryOutputSink::new();

    // Attempt to read beyond I/O limits
    let params = json!({
        "path": large_file.file_name().unwrap().to_string_lossy(),
        "len": 20 * 1024 * 1024 // Try to read 20MB
    });

    let result = runner
        .execute(&exec_context, params, &mut output_sink)
        .await?;

    // Should complete without crashing, may be truncated due to limits
    assert!(
        result.status == smith_protocol::ExecutionStatus::Ok
            || result.status == smith_protocol::ExecutionStatus::Error
    );

    // Should not have read more than the I/O limit allows
    assert!(
        result.stdout_bytes <= restrictive_limits.io_bytes,
        "Should respect I/O limits"
    );

    // Memory usage should be constrained
    // Note: We can't directly measure memory here, but the process should complete

    Ok(())
}

/// Test symlink attack prevention
#[tokio::test]
async fn test_symlink_attack_prevention() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("fs.read.v1")
        .expect("fs.read.v1 should be registered");

    // Create a legitimate file
    let target_file = temp_dir.path().join("target.txt");
    tokio::fs::write(&target_file, "Secret content").await?;

    // Create a symlink pointing outside the allowed area
    let symlink_path = temp_dir.path().join("symlink_attack");

    // Try to create symlink to /etc/passwd (will fail on systems without permission, but test the logic)
    let etc_passwd = PathBuf::from("/etc/passwd");
    if etc_passwd.exists() {
        let _ = std::os::unix::fs::symlink("/etc/passwd", &symlink_path);
    } else {
        // Create symlink to our target file for testing
        std::os::unix::fs::symlink(&target_file, &symlink_path)?;
    }

    // Attempt to read through symlink
    let symlink_intent = Intent::new(
        ProtoCapability::FsReadV1,
        "symlink-attack".to_string(),
        json!({ "path": symlink_path.file_name().unwrap().to_string_lossy() }),
        30000,
        "attacker".to_string(),
    );

    let exec_context = ExecCtx {
        workdir: temp_dir.path().to_path_buf(),
        limits: CapabilityExecutionLimits::default(),
        scope: ExecutionScope {
            paths: vec![],
            urls: vec![],
            env_vars: vec![],
            custom: HashMap::new(),
        },
        trace_id: "symlink-test".to_string(),
        sandbox: SandboxConfig {
            mode: SandboxMode::Full,
            landlock_enabled: true,
            seccomp_enabled: true,
            cgroups_enabled: true,
            namespaces_enabled: true,
        },
    };

    // Validation might catch this, or execution should handle it safely
    let validation_result = capability.validate(&symlink_intent);
    if validation_result.is_ok() {
        let execution_result = capability.execute(symlink_intent, exec_context).await;
        // If execution proceeds, it should either fail safely or be constrained by Landlock
        if let Ok(result) = execution_result {
            // If successful, should not contain system file content
            if let Some(output) = result.output {
                let content = output.to_string();
                assert!(
                    !content.contains("root:"),
                    "Should not read system password file"
                );
                assert!(!content.contains("/bin/"), "Should not read system files");
            }
        }
    }

    Ok(())
}

/// Test race condition exploitation attempts
#[tokio::test]
async fn test_race_condition_protection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = std::sync::Arc::new(register_builtin_capabilities());

    // Create a file that we'll try to manipulate during execution
    let race_file = temp_dir.path().join("race.txt");
    tokio::fs::write(&race_file, "Original content").await?;

    // Test that validation is stable under concurrent access
    let intent = Intent::new(
        ProtoCapability::FsReadV1,
        "race-test".to_string(),
        json!({ "path": "race.txt" }),
        30000,
        "test-user".to_string(),
    );

    // Spawn multiple concurrent validations
    let mut tasks = Vec::new();

    for i in 0..10 {
        let registry_ref = registry.clone();
        let intent_clone = intent.clone();

        let task = tokio::spawn(async move {
            let capability = registry_ref
                .get("fs.read.v1")
                .expect("fs.read.v1 should be registered");
            // All validations should be consistent
            let result = capability.validate(&intent_clone);
            (i, result)
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    let results: Vec<_> = futures::future::join_all(tasks).await;

    // All validations should succeed and be consistent
    for result in results {
        match result {
            Ok((task_id, validation_result)) => {
                assert!(
                    validation_result.is_ok(),
                    "Task {} validation should succeed",
                    task_id
                );
            }
            Err(e) => {
                panic!("Task panicked: {}", e);
            }
        }
    }

    Ok(())
}

/// Test privilege escalation prevention
#[tokio::test]
async fn test_privilege_escalation_prevention() -> Result<()> {
    let _temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("fs.read.v1")
        .expect("fs.read.v1 should be registered");

    // Attempt to access privileged system files
    let privileged_paths = vec![
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh/id_rsa",
        "/proc/1/environ",                 // Init process environment
        "/sys/kernel/debug/tracing/trace", // Kernel tracing
        "/dev/mem",                        // Physical memory device
        "/dev/kmem",                       // Kernel memory device
    ];

    for path in privileged_paths {
        let intent = Intent::new(
            ProtoCapability::FsReadV1,
            "privilege-escalation".to_string(),
            json!({ "path": path }),
            30000,
            "attacker".to_string(),
        );

        // Should be blocked at validation
        let validation_result = capability.validate(&intent);
        assert!(
            validation_result.is_err(),
            "Privileged file access should be blocked: {}",
            path
        );
    }

    Ok(())
}

/// Test container escape prevention
#[tokio::test]
async fn test_container_escape_prevention() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let registry = register_builtin_capabilities();

    let capability = registry
        .get("fs.read.v1")
        .expect("fs.read.v1 should be registered");

    // Attempt to access container runtime files that could enable escape
    let container_escape_paths = vec![
        "/proc/self/mountinfo",                        // Mount information
        "/proc/mounts",                                // Mount points
        "/proc/self/cgroup",                           // Control group info
        "/sys/fs/cgroup/memory/memory.limit_in_bytes", // Memory limits
        "/var/run/docker.sock",                        // Docker socket
        "/run/containerd/containerd.sock",             // Containerd socket
        "/../../../proc/1/root/etc/passwd",            // Escape to host root
    ];

    for path in container_escape_paths {
        let intent = Intent::new(
            ProtoCapability::FsReadV1,
            "container-escape".to_string(),
            json!({ "path": path }),
            30000,
            "attacker".to_string(),
        );

        // Should be blocked at validation or execution
        let validation_result = capability.validate(&intent);
        if validation_result.is_ok() {
            let exec_context = ExecCtx {
                workdir: temp_dir.path().to_path_buf(),
                limits: CapabilityExecutionLimits::default(),
                scope: ExecutionScope {
                    paths: vec![],
                    urls: vec![],
                    env_vars: vec![],
                    custom: HashMap::new(),
                },
                trace_id: "escape-test".to_string(),
                sandbox: SandboxConfig {
                    mode: SandboxMode::Full,
                    landlock_enabled: true,
                    seccomp_enabled: true,
                    cgroups_enabled: true,
                    namespaces_enabled: true,
                },
            };

            let execution_result = capability.execute(intent, exec_context).await;
            assert!(
                execution_result.is_err()
                    || execution_result.unwrap().status == smith_protocol::ExecutionStatus::Error,
                "Container escape attempt should fail: {}",
                path
            );
        }
    }

    Ok(())
}

/// Test malformed input handling
#[tokio::test]
async fn test_malformed_input_handling() -> Result<()> {
    let registry = register_builtin_capabilities();

    let fs_capability = registry
        .get("fs.read.v1")
        .expect("fs.read.v1 should be registered");

    let http_capability = registry
        .get("http.fetch.v1")
        .expect("http.fetch.v1 should be registered");

    // Test malformed fs.read.v1 inputs
    let malformed_fs_inputs = vec![
        json!({}),                                                        // Missing required fields
        json!({"path": 123}),                                             // Wrong type
        json!({"path": null}),                                            // Null value
        json!({"path": ""}),                                              // Empty path
        json!({"path": "test.txt", "len": -1}),                           // Negative length
        json!({"path": "test.txt", "len": "invalid"}),                    // Invalid length type
        json!({"path": "\x00\x01\x02\x03"}),                              // Binary data in path
        json!({"path": "a".repeat(1000)}),                                // Extremely long path
        json!({"path": "test.txt", "extra_field": "should_not_be_here"}), // Extra fields
    ];

    for (i, malformed_input) in malformed_fs_inputs.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::FsReadV1,
            format!("malformed-fs-{}", i),
            malformed_input.clone(),
            30000,
            "attacker".to_string(),
        );

        let validation_result = fs_capability.validate(&intent);
        assert!(
            validation_result.is_err(),
            "Malformed fs input should be rejected: {}",
            malformed_input
        );
    }

    // Test malformed http.fetch.v1 inputs
    let malformed_http_inputs = vec![
        json!({}),                                                        // Missing required fields
        json!({"url": 123}),                                              // Wrong type
        json!({"url": "not-a-url"}),                                      // Invalid URL format
        json!({"url": "http://example.com", "method": "INVALID"}),        // Invalid HTTP method
        json!({"url": "http://example.com", "timeout": -1}),              // Negative timeout
        json!({"url": "http://example.com", "headers": "not-an-object"}), // Invalid headers type
        json!({"url": "ftp://example.com"}),                              // Unsupported protocol
        json!({"url": format!("http://{}.com", "x".repeat(2000))}),       // Extremely long URL
    ];

    for (i, malformed_input) in malformed_http_inputs.iter().enumerate() {
        let intent = Intent::new(
            ProtoCapability::HttpFetchV1,
            format!("malformed-http-{}", i),
            malformed_input.clone(),
            30000,
            "attacker".to_string(),
        );

        let validation_result = http_capability.validate(&intent);
        assert!(
            validation_result.is_err(),
            "Malformed http input should be rejected: {}",
            malformed_input
        );
    }

    Ok(())
}
