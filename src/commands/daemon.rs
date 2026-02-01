/*!
 * Daemon command implementation
 *
 * Extracted from main.rs to reduce complexity and improve maintainability.
 * Handles the main executor daemon startup and worker management.
 */

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::bootstrap::{setup_signal_handlers, validate_security_capabilities};
use crate::config::{self, Config};
use crate::{
    audit, health, idempotency, metrics, nats, policy, runners, schema, security,
    vm::{MicroVmManager, VmPoolRuntimeConfig},
};
use smith_config::PolicyDerivations;

/// Handles the daemon command
pub struct DaemonCommand;

impl DaemonCommand {
    pub async fn execute(
        config_path: PathBuf,
        demo_mode: bool,
        autobootstrap: bool,
        capability_digest: String,
    ) -> Result<()> {
        log_daemon_startup(demo_mode);
        let validated_capability_digest = validate_capability_digest(capability_digest)?;
        let config = load_and_validate_config(&config_path).await?;
        let derivations = load_policy_derivations(&config).await?;

        validate_security_capabilities(&config, demo_mode)?;

        let daemon_services = initialize_daemon_services(&config).await?;
        let nats_clients = initialize_nats_clients(&config, autobootstrap).await?;
        let execution_components = initialize_execution_components(&config).await?;

        let _policy_sync = execution_components
            .policy_engine
            .start_policy_listener(nats_clients.nats_client.clone(), &config.executor.policy)
            .await?;

        let worker_handles = start_worker_pools(
            &config,
            nats_clients.nats_client,
            execution_components.idempotency_store,
            execution_components.policy_engine,
            execution_components.schema_validator,
            execution_components.runner_registry,
            execution_components.trusted_signers,
            daemon_services.metrics_handle,
            daemon_services.audit_logger,
            validated_capability_digest,
            derivations,
        )
        .await?;

        info!("All worker pools started. Executor is ready to process intents.");
        setup_signal_handlers().await;

        futures::future::try_join_all(worker_handles).await?;
        info!("Executor daemon shutting down");
        Ok(())
    }
}

pub struct DaemonServices {
    pub audit_logger: Arc<tokio::sync::Mutex<audit::AuditLogger>>,
    pub metrics_handle: Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
}

pub struct NatsClients {
    pub nats_client: nats::NatsClient,
    pub _smith_bus: smith_bus::SmithBus,
}

pub struct ExecutionComponents {
    pub idempotency_store: idempotency::IdempotencyStore,
    pub policy_engine: policy::PolicyEngine,
    pub schema_validator: Arc<schema::SchemaValidator>,
    pub runner_registry: Arc<runners::RunnerRegistry>,
    pub trusted_signers: Arc<security::TrustedSigners>,
    pub vm_manager: Option<Arc<MicroVmManager>>,
}

fn log_daemon_startup(demo_mode: bool) {
    if demo_mode {
        warn!("⚠️  RUNNING IN DEMO MODE - SECURITY FEATURES DISABLED ⚠️");
        warn!("⚠️  THIS IS UNSAFE FOR PRODUCTION USE ⚠️");
    }
    info!("🚀 Starting Smith Executor Daemon");
}

fn validate_capability_digest(capability_digest: String) -> Result<String> {
    if capability_digest.len() != 64 || !capability_digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "Invalid capability digest format. Expected 64 hex characters, got: {}",
            capability_digest
        ));
    }
    info!("Capability digest validated: {}", capability_digest);
    Ok(capability_digest)
}

async fn load_and_validate_config(config_path: &PathBuf) -> Result<Config> {
    let config = config::load_config(config_path)?;
    info!(
        "Configuration loaded successfully from {}",
        config_path.display()
    );
    Ok(config)
}

async fn load_policy_derivations(config: &Config) -> Result<Arc<PolicyDerivations>> {
    let derivations =
        config::load_policy_derivations(config).context("Failed to load policy derivations")?;
    info!(
        "Policy derivations loaded successfully with {} capabilities",
        derivations.seccomp_allow.len()
    );
    Ok(Arc::new(derivations))
}

async fn initialize_daemon_services(config: &Config) -> Result<DaemonServices> {
    // Initialize audit logging
    let audit_logger = Arc::new(tokio::sync::Mutex::new(audit::AuditLogger::new(
        &config.executor.audit_dir,
    )?));

    // Initialize and start metrics services
    let metrics_exporter = metrics::MetricsExporter::new(config)?;
    let metrics_handle = metrics_exporter.metrics();

    // Start metrics HTTP server in background (if configured)
    if let Some(metrics_port) = config.executor.metrics_port {
        let metrics_server = metrics_exporter.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics_server.start_http_server(metrics_port).await {
                error!("Metrics HTTP server failed: {}", e);
            }
        });
        info!("Metrics server will start on port {}", metrics_port);
    }

    // Start health HTTP server in background
    let health_port = config.executor.metrics_port.map(|p| p + 1);
    let _health_service = health::setup_health_service(health_port).await?;
    info!("Health service initialized{}", &{
        if let Some(port) = health_port {
            format!(" on port {}", port)
        } else {
            String::new()
        }
    });

    Ok(DaemonServices {
        audit_logger,
        metrics_handle,
    })
}

async fn initialize_nats_clients(config: &Config, autobootstrap: bool) -> Result<NatsClients> {
    // Initialize NATS client and JetStream consumers
    let nats_client = nats::NatsClient::new(&config.executor.nats_config).await?;
    info!("Connected to NATS server");

    if let Err(err) = nats_client.maybe_spawn_debug_result_tap().await {
        warn!("Failed to start executor debug result tap: {err}");
    }

    // Initialize Smith Bus for enhanced JetStream operations
    let smith_bus = smith_bus::SmithBus::connect(&config.nats.url).await?;

    // Bootstrap JetStream streams if requested
    if autobootstrap {
        info!("Bootstrapping JetStream streams...");
        let stream_manager = smith_bus.stream_manager();
        stream_manager
            .bootstrap_streams()
            .await
            .context("Failed to bootstrap JetStream streams")?;
        info!("JetStream streams bootstrapped successfully");
    }

    Ok(NatsClients {
        nats_client,
        _smith_bus: smith_bus,
    })
}

async fn initialize_execution_components(config: &Config) -> Result<ExecutionComponents> {
    // Initialize idempotency store
    let idempotency_store = idempotency::IdempotencyStore::new(&config.executor.state_dir).await?;
    info!("Idempotency store initialized");

    // Initialize policy engine
    let policy_engine = policy::PolicyEngine::new(config)?;
    info!(
        "Policy engine initialized with {} policies",
        policy_engine.policy_count()
    );

    // Initialize schema validator
    let schema_validator = Arc::new(schema::SchemaValidator::new()?);
    info!("Schema validator initialized");

    // Initialize capability registry
    let _capability_registry = Arc::new(crate::capabilities::register_builtin_capabilities());
    info!(
        "Capability registry initialized with {} capabilities",
        _capability_registry.list().len()
    );

    // Initialize micro-VM manager (optional)
    let vm_manager = if config.executor.vm_pool.enabled {
        let runtime_config = VmPoolRuntimeConfig::from(&config.executor.vm_pool);
        match MicroVmManager::new(runtime_config) {
            Ok(manager) => {
                info!(
                    volume_root = %config.executor.vm_pool.volume_root.display(),
                    "Micro-VM pool initialized"
                );
                Some(manager)
            }
            Err(err) => {
                warn!(
                    error = %err,
                    "Failed to initialize micro-VM pool; continuing without persistent shells"
                );
                None
            }
        }
    } else {
        None
    };

    // Initialize runner registry
    let runner_registry = Arc::new(runners::RunnerRegistry::new(vm_manager.clone()));
    info!("Runner registry initialized");

    let trusted_signers = Arc::new(
        security::TrustedSigners::load_from_dir(&config.executor.security.pubkeys_dir)
            .context("Failed to load trusted signer keys")?,
    );
    if trusted_signers.is_empty() {
        warn!(
            "No trusted signer keys loaded from {}",
            config.executor.security.pubkeys_dir.display()
        );
    }

    Ok(ExecutionComponents {
        idempotency_store,
        policy_engine,
        schema_validator,
        runner_registry,
        trusted_signers,
        vm_manager,
    })
}

#[allow(clippy::too_many_arguments)]
async fn start_worker_pools(
    config: &Config,
    nats_client: nats::NatsClient,
    idempotency_store: idempotency::IdempotencyStore,
    policy_engine: policy::PolicyEngine,
    schema_validator: Arc<schema::SchemaValidator>,
    runner_registry: Arc<runners::RunnerRegistry>,
    trusted_signers: Arc<security::TrustedSigners>,
    metrics_handle: Arc<tokio::sync::RwLock<metrics::ExecutorMetrics>>,
    audit_logger: Arc<tokio::sync::Mutex<audit::AuditLogger>>,
    capability_digest: String,
    derivations: Arc<PolicyDerivations>,
) -> Result<Vec<tokio::task::JoinHandle<Result<()>>>> {
    let mut worker_handles = Vec::new();

    for (capability, stream_config) in &config.executor.intent_streams {
        info!("Starting worker pool for capability: {}", capability);
        for worker_id in 0..stream_config.workers {
            let handle = tokio::spawn(crate::worker::run_worker(
                capability.clone(),
                worker_id,
                nats_client.clone(),
                idempotency_store.clone(),
                policy_engine.clone(),
                schema_validator.clone(),
                runner_registry.clone(),
                trusted_signers.clone(),
                config.clone(),
                metrics_handle.clone(),
                audit_logger.clone(),
                capability_digest.clone(),
                derivations.clone(),
            ));
            worker_handles.push(handle);
        }
    }

    Ok(worker_handles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_capability_digest_valid() {
        let valid_digest = "a".repeat(64);
        let result = validate_capability_digest(valid_digest.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_digest);
    }

    #[test]
    fn test_validate_capability_digest_valid_hex() {
        let valid_digest = "0123456789abcdef".repeat(4);
        let result = validate_capability_digest(valid_digest.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_digest);
    }

    #[test]
    fn test_validate_capability_digest_mixed_case() {
        let valid_digest = "AbCdEf0123456789".repeat(4);
        let result = validate_capability_digest(valid_digest.clone());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_capability_digest_too_short() {
        let short_digest = "abc123".to_string();
        let result = validate_capability_digest(short_digest);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid capability digest format"));
    }

    #[test]
    fn test_validate_capability_digest_too_long() {
        let long_digest = "a".repeat(65);
        let result = validate_capability_digest(long_digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_digest_non_hex() {
        let invalid_digest = "g".repeat(64); // 'g' is not hex
        let result = validate_capability_digest(invalid_digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_digest_empty() {
        let result = validate_capability_digest(String::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_digest_spaces() {
        let invalid_digest = format!("{}  {}", "a".repeat(31), "b".repeat(31));
        let result = validate_capability_digest(invalid_digest);
        assert!(result.is_err());
    }

    #[test]
    fn test_log_daemon_startup_demo_mode() {
        // Just verify it doesn't panic
        log_daemon_startup(true);
    }

    #[test]
    fn test_log_daemon_startup_normal_mode() {
        // Just verify it doesn't panic
        log_daemon_startup(false);
    }

    #[test]
    fn test_daemon_services_struct() {
        // Test struct can be created (requires async context in real usage)
        assert!(std::mem::size_of::<DaemonServices>() > 0);
    }

    #[test]
    fn test_nats_clients_struct() {
        assert!(std::mem::size_of::<NatsClients>() > 0);
    }

    #[test]
    fn test_execution_components_struct() {
        assert!(std::mem::size_of::<ExecutionComponents>() > 0);
    }

    #[test]
    fn test_daemon_command_struct() {
        let _cmd = DaemonCommand;
        assert!(std::mem::size_of::<DaemonCommand>() == 0); // Zero-sized type
    }
}
