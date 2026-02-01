use crate::capability::CapabilityRegistry;

pub mod archive_read_v1;
pub mod bench_report_v1;
pub mod fs_read_v1;
pub mod http_fetch_v1;
pub mod sqlite_query_v1;

// Utility modules
pub mod benchmark_statistics;
pub mod http_fetch_validation;
pub mod sqlite_validation;

// Security test modules
#[cfg(test)]
pub mod fs_read_security_tests;
#[cfg(test)]
pub mod http_fetch_security_tests;

/// Initialize and register all built-in capabilities
pub fn register_builtin_capabilities() -> CapabilityRegistry {
    let mut registry = CapabilityRegistry::new();

    // Register filesystem capabilities
    registry.register(Box::new(fs_read_v1::FsReadV1Capability::new()));

    // Register HTTP capabilities
    registry.register(Box::new(http_fetch_v1::HttpFetchV1Capability::new()));

    // TODO: Register archive capabilities (Phase 8 Extended) after refactoring is complete
    // registry.register(Box::new(archive_read_v1::ArchiveReadV1Capability::new()));

    // Register database capabilities (Phase 8 Extended)
    registry.register(Box::new(sqlite_query_v1::SqliteQueryV1Capability::new()));

    // Register benchmark capabilities (Phase 8 Extended)
    registry.register(Box::new(bench_report_v1::BenchReportV1Capability::new()));

    tracing::info!("Registered {} built-in capabilities", registry.list().len());
    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_builtin_capabilities() {
        let registry = register_builtin_capabilities();
        let capability_names = registry.list();

        // Verify expected capabilities are registered
        assert!(
            !capability_names.is_empty(),
            "Should register at least one capability"
        );

        // Check for core security-critical capabilities
        assert!(
            capability_names.contains(&"fs.read.v1".to_string()),
            "Should register fs.read.v1 capability"
        );
        assert!(
            capability_names.contains(&"http.fetch.v1".to_string()),
            "Should register http.fetch.v1 capability"
        );
        assert!(
            capability_names.contains(&"sqlite.query.v1".to_string()),
            "Should register sqlite.query.v1 capability"
        );
        assert!(
            capability_names.contains(&"bench.report.v1".to_string()),
            "Should register bench.report.v1 capability"
        );

        // Verify minimum expected number of capabilities
        assert!(
            capability_names.len() >= 4,
            "Should register at least 4 capabilities, got: {}",
            capability_names.len()
        );

        println!("Registered capabilities: {:?}", capability_names);
    }

    #[test]
    fn test_capability_registry_security_properties() {
        let registry = register_builtin_capabilities();
        let capability_names = registry.list();

        for name in capability_names {
            // Security requirement: All capability names must follow versioned pattern
            assert!(
                name.contains(".v"),
                "Capability '{}' must have version suffix",
                name
            );

            // Security requirement: All capabilities must have non-empty names
            assert!(!name.is_empty(), "Capability name cannot be empty");

            // Security requirement: Capability names must not contain dangerous characters
            assert!(
                !name.contains(".."),
                "Capability '{}' must not contain path traversal",
                name
            );
            assert!(
                !name.contains("/"),
                "Capability '{}' must not contain path separators",
                name
            );
            assert!(
                !name.contains("\\"),
                "Capability '{}' must not contain backslashes",
                name
            );

            // Security requirement: Names must be lowercase with dots and underscores only
            assert!(
                name.chars()
                    .all(|c| c.is_lowercase() || c.is_numeric() || c == '.' || c == '_'),
                "Capability '{}' must use only lowercase, numbers, dots, and underscores",
                name
            );
        }
    }

    #[test]
    fn test_capability_registry_uniqueness() {
        let registry = register_builtin_capabilities();
        let capability_names = registry.list();
        let mut seen_names = std::collections::HashSet::new();

        for name in &capability_names {
            assert!(
                !seen_names.contains(name),
                "Duplicate capability name detected: '{}'",
                name
            );
            seen_names.insert(name.clone());
        }

        // Verify no duplicates
        assert_eq!(
            seen_names.len(),
            capability_names.len(),
            "All capability names should be unique"
        );
    }

    #[test]
    fn test_capability_registry_consistency() {
        // Run registration multiple times to ensure consistency
        let registry1 = register_builtin_capabilities();
        let registry2 = register_builtin_capabilities();

        let caps1: Vec<String> = registry1.list();
        let caps2: Vec<String> = registry2.list();

        assert_eq!(
            caps1.len(),
            caps2.len(),
            "Registry should be consistent across calls"
        );

        // Sort for comparison
        let mut sorted_caps1 = caps1.clone();
        let mut sorted_caps2 = caps2.clone();
        sorted_caps1.sort();
        sorted_caps2.sort();

        assert_eq!(
            sorted_caps1, sorted_caps2,
            "Registry should produce identical results"
        );
    }

    #[test]
    fn test_specific_capability_presence() {
        let registry = register_builtin_capabilities();

        // Test that we can retrieve specific capabilities
        assert!(
            registry.get("fs.read.v1").is_some(),
            "Should be able to retrieve fs.read.v1 capability"
        );
        assert!(
            registry.get("http.fetch.v1").is_some(),
            "Should be able to retrieve http.fetch.v1 capability"
        );
        assert!(
            registry.get("sqlite.query.v1").is_some(),
            "Should be able to retrieve sqlite.query.v1 capability"
        );
        assert!(
            registry.get("bench.report.v1").is_some(),
            "Should be able to retrieve bench.report.v1 capability"
        );

        // Test that invalid capabilities return None
        assert!(
            registry.get("invalid.capability.v1").is_none(),
            "Should return None for invalid capabilities"
        );
        assert!(
            registry.get("").is_none(),
            "Should return None for empty capability name"
        );
    }

    #[test]
    fn test_registry_security_boundaries() {
        let registry = register_builtin_capabilities();

        // Test that registry rejects malicious capability names
        let malicious_names = [
            "../../../etc/passwd",
            "exec.shell.v1",
            "fs.write.v1",      // Should not exist in read-only executor
            "network.raw.v1",   // Should not exist - dangerous
            "process.spawn.v1", // Should not exist - dangerous
        ];

        for malicious_name in malicious_names {
            assert!(
                registry.get(malicious_name).is_none(),
                "Should not register dangerous capability: '{}'",
                malicious_name
            );
        }
    }

    #[test]
    fn test_capability_registry_thread_safety() {
        use std::thread;

        // Test that registry creation is thread-safe
        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    let registry = register_builtin_capabilities();
                    registry.list().len()
                })
            })
            .collect();

        let results: Vec<usize> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All threads should get the same number of capabilities
        let first_count = results[0];
        assert!(
            results.iter().all(|&count| count == first_count),
            "Registry creation should be consistent across threads"
        );
    }
}
