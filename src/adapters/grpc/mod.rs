//! gRPC ingest adapter using tonic
//!
//! This adapter provides direct mode communication using gRPC, supporting
//! both unary and streaming execution requests. It's the primary adapter
//! for workstation mode where clients connect directly to agentd.

use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;

use crate::core::ingest::{
    AdapterConfigInfo, AdapterStats, HealthStatus, IngestAdapter, IntentHandler, OutputChunk,
    RequestContext,
};
use crate::core::intent::{
    IntentRequest, IntentResponse, IntentStatus, RequestConstraints, RequestMetadata,
    SandboxPreferences,
};

// Include generated proto code
pub mod proto {
    tonic::include_proto!("agentd.v1");
}

use proto::agentd_server::{Agentd, AgentdServer};
use proto::{
    AttachSandboxRequest, AttachSandboxResponse, CreateSandboxRequest, CreateSandboxResponse,
    ExecuteOutput, ExecuteRequest, ExecuteResponse, ExecutionResult, ExecutionStatus,
    GetSandboxCapabilitiesRequest, HealthRequest, HealthResponse, ListCapabilitiesRequest,
    ListCapabilitiesResponse, ListSandboxesRequest, ListSandboxesResponse, SandboxCapabilities,
    TerminateSandboxRequest, TerminateSandboxResponse,
};

/// Configuration for the gRPC adapter
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// Listen address (e.g., "0.0.0.0:9500")
    pub listen_address: SocketAddr,

    /// TLS certificate path (optional)
    pub tls_cert_path: Option<String>,

    /// TLS key path (optional)
    pub tls_key_path: Option<String>,

    /// Maximum concurrent streams
    pub max_concurrent_streams: Option<u32>,

    /// Maximum frame size
    pub max_frame_size: Option<u32>,

    /// Connection keepalive interval in seconds
    pub keepalive_interval_secs: Option<u64>,

    /// Request timeout in seconds
    pub request_timeout_secs: Option<u64>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:9500".parse().unwrap(),
            tls_cert_path: None,
            tls_key_path: None,
            max_concurrent_streams: Some(100),
            max_frame_size: Some(16 * 1024 * 1024), // 16MB
            keepalive_interval_secs: Some(30),
            request_timeout_secs: Some(300),
        }
    }
}

/// gRPC ingest adapter
pub struct GrpcAdapter {
    config: GrpcConfig,
    handler: RwLock<Option<Arc<dyn IntentHandler>>>,
    running: AtomicBool,
    stats: AdapterStatsInner,
    shutdown_tx: RwLock<Option<tokio::sync::oneshot::Sender<()>>>,
}

struct AdapterStatsInner {
    requests_received: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    requests_in_flight: AtomicU64,
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    active_connections: AtomicU64,
}

impl GrpcAdapter {
    pub fn new(config: GrpcConfig) -> Self {
        Self {
            config,
            handler: RwLock::new(None),
            running: AtomicBool::new(false),
            stats: AdapterStatsInner {
                requests_received: AtomicU64::new(0),
                requests_succeeded: AtomicU64::new(0),
                requests_failed: AtomicU64::new(0),
                requests_in_flight: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                active_connections: AtomicU64::new(0),
            },
            shutdown_tx: RwLock::new(None),
        }
    }

    /// Create a new adapter with default configuration
    pub fn with_address(address: SocketAddr) -> Self {
        Self::new(GrpcConfig {
            listen_address: address,
            ..Default::default()
        })
    }
}

#[async_trait]
impl IngestAdapter for GrpcAdapter {
    fn name(&self) -> &str {
        "grpc"
    }

    async fn start(&self, handler: Arc<dyn IntentHandler>) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Adapter is already running"));
        }

        // Store the handler
        {
            let mut h = self.handler.write().await;
            *h = Some(handler.clone());
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        {
            let mut tx = self.shutdown_tx.write().await;
            *tx = Some(shutdown_tx);
        }

        // Create the gRPC service
        let service = GrpcService {
            handler: handler.clone(),
            stats: Arc::new(ServiceStats {
                requests_received: AtomicU64::new(0),
                requests_succeeded: AtomicU64::new(0),
                requests_failed: AtomicU64::new(0),
                requests_in_flight: AtomicU64::new(0),
            }),
        };

        let addr = self.config.listen_address;

        info!("Starting gRPC server on {}", addr);

        // Build the server
        let server = Server::builder()
            .add_service(AgentdServer::new(service))
            .serve_with_shutdown(addr, async {
                let _ = shutdown_rx.await;
                info!("gRPC server received shutdown signal");
            });

        self.running.store(true, Ordering::SeqCst);

        // Spawn the server in a background task
        tokio::spawn(async move {
            if let Err(e) = server.await {
                error!("gRPC server error: {}", e);
            }
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        info!("gRPC adapter started on {}", addr);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("Stopping gRPC adapter");

        // Send shutdown signal
        {
            let mut tx = self.shutdown_tx.write().await;
            if let Some(shutdown_tx) = tx.take() {
                let _ = shutdown_tx.send(());
            }
        }

        // Clear the handler
        {
            let mut h = self.handler.write().await;
            *h = None;
        }

        self.running.store(false, Ordering::SeqCst);

        info!("gRPC adapter stopped");
        Ok(())
    }

    async fn health(&self) -> HealthStatus {
        if !self.running.load(Ordering::SeqCst) {
            return HealthStatus::Unhealthy {
                reason: "Adapter is not running".to_string(),
            };
        }

        // Check if we have a handler
        let handler = self.handler.read().await;
        if handler.is_none() {
            return HealthStatus::Unhealthy {
                reason: "No handler configured".to_string(),
            };
        }

        HealthStatus::Healthy
    }

    async fn stats(&self) -> AdapterStats {
        AdapterStats {
            requests_received: self.stats.requests_received.load(Ordering::Relaxed),
            requests_in_flight: self.stats.requests_in_flight.load(Ordering::Relaxed),
            requests_succeeded: self.stats.requests_succeeded.load(Ordering::Relaxed),
            requests_failed: self.stats.requests_failed.load(Ordering::Relaxed),
            avg_latency_ms: 0.0, // TODO: Implement latency tracking
            p95_latency_ms: 0.0,
            p99_latency_ms: 0.0,
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            active_connections: self.stats.active_connections.load(Ordering::Relaxed),
            custom_metrics: vec![],
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn config_info(&self) -> AdapterConfigInfo {
        AdapterConfigInfo {
            adapter_type: "grpc".to_string(),
            listen_address: Some(self.config.listen_address.to_string()),
            remote_address: None,
            tls_enabled: self.config.tls_cert_path.is_some(),
            auth_methods: vec!["mtls".to_string(), "jwt".to_string(), "api-key".to_string()],
            max_concurrent: self.config.max_concurrent_streams,
            extra: vec![],
        }
    }
}

/// Internal stats for the service
struct ServiceStats {
    requests_received: AtomicU64,
    requests_succeeded: AtomicU64,
    requests_failed: AtomicU64,
    requests_in_flight: AtomicU64,
}

/// gRPC service implementation
struct GrpcService {
    handler: Arc<dyn IntentHandler>,
    stats: Arc<ServiceStats>,
}

impl GrpcService {
    fn build_request_context(&self, request_id: &str) -> RequestContext {
        RequestContext {
            request_id: request_id.to_string(),
            source_adapter: "grpc".to_string(),
            client_id: String::new(), // TODO: Extract from TLS or metadata
            received_at: chrono::Utc::now(),
            reply_to: None,
            supports_streaming: true,
            metadata: vec![],
        }
    }

    fn convert_request(&self, req: &ExecuteRequest) -> IntentRequest {
        // Parse request_id as UUID, or generate new one
        let id = Uuid::parse_str(&req.request_id).unwrap_or_else(|_| Uuid::new_v4());

        IntentRequest {
            id,
            capability: req.capability.clone(),
            version: req.version,
            params: serde_json::from_str(&req.params_json).unwrap_or(serde_json::Value::Null),
            constraints: req
                .constraints
                .as_ref()
                .map(|c| RequestConstraints {
                    max_duration_ms: Some(c.max_duration_ms),
                    max_output_bytes: Some(c.max_output_bytes),
                    max_memory_bytes: Some(c.max_memory_bytes),
                    allow_network: Some(c.allow_network),
                    allow_writes: Some(c.allow_writes),
                })
                .unwrap_or_default(),
            metadata: req
                .metadata
                .as_ref()
                .map(|m| RequestMetadata {
                    trace_id: Some(m.trace_id.clone()).filter(|s| !s.is_empty()),
                    span_id: Some(m.span_id.clone()).filter(|s| !s.is_empty()),
                    timestamp_ms: Some(chrono::Utc::now().timestamp_millis() as u64),
                    idempotency_key: Some(m.idempotency_key.clone()).filter(|s| !s.is_empty()),
                    priority: Some(m.priority as u8),
                    custom: m.custom.clone(),
                })
                .unwrap_or_default(),
            sandbox_prefs: req
                .sandbox_prefs
                .as_ref()
                .map(|p| SandboxPreferences {
                    sandbox_id: Some(p.sandbox_id.clone()).filter(|s| !s.is_empty()),
                    require_fresh: p.require_fresh,
                    profile: Some(p.profile.clone()).filter(|s| !s.is_empty()),
                    persist: p.persist,
                    backend: Some(p.backend.clone()).filter(|s| !s.is_empty()),
                    labels: std::collections::HashMap::new(),
                })
                .unwrap_or_default(),
        }
    }

    fn convert_response(&self, resp: IntentResponse) -> ExecuteResponse {
        let status = match resp.status {
            IntentStatus::Ok => ExecutionStatus::Ok as i32,
            IntentStatus::Denied => ExecutionStatus::Denied as i32,
            IntentStatus::Error => ExecutionStatus::Error as i32,
            IntentStatus::Expired => ExecutionStatus::Expired as i32,
            IntentStatus::Cancelled => ExecutionStatus::Cancelled as i32,
            IntentStatus::Pending => ExecutionStatus::Pending as i32,
        };

        let result = resp.result.map(|r| ExecutionResult {
            exit_code: r.exit_code,
            stdout: r.stdout.clone().unwrap_or_default(),
            stdout_bytes: r.stdout_bytes.clone().unwrap_or_default(),
            stderr: r.stderr.unwrap_or_default(),
            output_json: r.output.map(|v| v.to_string()).unwrap_or_default(),
            artifacts: r
                .artifacts
                .into_iter()
                .map(|a| proto::Artifact {
                    name: a.name,
                    content_type: a.content_type,
                    size: a.size,
                    sha256: a.sha256,
                    uri: a.uri.unwrap_or_default(),
                    content: a.content.unwrap_or_default(),
                })
                .collect(),
            resource_usage: r.resource_usage.map(|u| proto::ResourceUsage {
                peak_memory_bytes: u.peak_memory_bytes,
                cpu_time_ms: u.cpu_time_ms,
                wall_time_ms: u.wall_time_ms,
                disk_write_bytes: u.disk_write_bytes,
                disk_read_bytes: u.disk_read_bytes,
                network_tx_bytes: u.network_tx_bytes,
                network_rx_bytes: u.network_rx_bytes,
            }),
        });

        let error = resp.error.map(|e| proto::ErrorDetails {
            code: e.code,
            message: e.message,
            details_json: e.details.map(|v| v.to_string()).unwrap_or_default(),
            retryable: e.retryable,
            retry_after_ms: e.retry_after_ms.unwrap_or(0),
        });

        let timing = Some(proto::ResponseTiming {
            received_at_ms: resp.timing.received_at_ms,
            started_at_ms: resp.timing.started_at_ms,
            completed_at_ms: resp.timing.completed_at_ms,
            queue_time_ms: resp.timing.queue_time_ms,
            setup_time_ms: resp.timing.setup_time_ms,
            exec_time_ms: resp.timing.exec_time_ms,
            total_time_ms: resp.timing.total_time_ms,
        });

        ExecuteResponse {
            request_id: resp.request_id.to_string(),
            status,
            code: resp.code,
            message: resp.message,
            result,
            error,
            timing,
            sandbox_info: resp.sandbox_info.map(|s| proto::SandboxInfo {
                sandbox_id: s.sandbox_id,
                backend: s.backend,
                profile: s.profile,
                newly_created: s.newly_created,
                capabilities: Some(proto::SandboxCapabilities {
                    sandbox_id: String::new(),
                    backend: String::new(),
                    profile: String::new(),
                    can_write_filesystem: s.capabilities.can_write,
                    readable_paths: s.capabilities.readable_paths,
                    writable_paths: s.capabilities.writable_paths,
                    has_network: s.capabilities.has_network,
                    allowed_destinations: vec![],
                    limits: Some(proto::ResourceLimits {
                        max_memory_bytes: s.capabilities.limits.max_memory_bytes.unwrap_or(0),
                        max_cpu_time_ms: s.capabilities.limits.max_cpu_ms.unwrap_or(0),
                        max_wall_time_ms: s.capabilities.limits.max_wall_ms.unwrap_or(0),
                        max_processes: 0,
                        max_open_files: 0,
                        max_output_bytes: s.capabilities.limits.max_output_bytes.unwrap_or(0),
                        max_write_bytes: 0,
                    }),
                    syscall_filter_active: false,
                    blocked_syscall_categories: vec![],
                    is_persistent: false,
                    created_at_ms: 0,
                    time_remaining_ms: 0,
                }),
            }),
        }
    }
}

#[tonic::async_trait]
impl Agentd for GrpcService {
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        self.stats.requests_received.fetch_add(1, Ordering::Relaxed);
        self.stats.requests_in_flight.fetch_add(1, Ordering::Relaxed);

        let req = request.into_inner();
        let ctx = self.build_request_context(&req.request_id);
        let intent_request = self.convert_request(&req);

        let result = self.handler.handle(intent_request, ctx).await;

        self.stats.requests_in_flight.fetch_sub(1, Ordering::Relaxed);

        match result {
            Ok(response) => {
                self.stats.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                Ok(Response::new(self.convert_response(response)))
            }
            Err(e) => {
                self.stats.requests_failed.fetch_add(1, Ordering::Relaxed);
                error!("Execute error: {}", e);
                Err(Status::internal(format!("Execution failed: {}", e)))
            }
        }
    }

    type ExecuteStreamStream =
        std::pin::Pin<Box<dyn futures::Stream<Item = Result<ExecuteOutput, Status>> + Send>>;

    async fn execute_stream(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStreamStream>, Status> {
        self.stats.requests_received.fetch_add(1, Ordering::Relaxed);
        self.stats.requests_in_flight.fetch_add(1, Ordering::Relaxed);

        let req = request.into_inner();
        let ctx = self.build_request_context(&req.request_id);
        let intent_request = self.convert_request(&req);

        // Create channel for streaming output
        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<OutputChunk>(100);
        let (stream_tx, stream_rx) =
            tokio::sync::mpsc::channel::<Result<ExecuteOutput, Status>>(100);

        let handler = self.handler.clone();
        let stats = self.stats.clone();

        // Spawn handler
        tokio::spawn(async move {
            // Forward output chunks to stream
            let stream_tx_clone = stream_tx.clone();
            let forward_handle = tokio::spawn(async move {
                while let Some(chunk) = output_rx.recv().await {
                    let output = match chunk {
                        OutputChunk::Stdout(data) => ExecuteOutput {
                            output: Some(proto::execute_output::Output::StdoutChunk(data)),
                        },
                        OutputChunk::Stderr(data) => ExecuteOutput {
                            output: Some(proto::execute_output::Output::StderrChunk(data)),
                        },
                        OutputChunk::Progress { percent, message } => ExecuteOutput {
                            output: Some(proto::execute_output::Output::Progress(proto::Progress {
                                percent,
                                message,
                            })),
                        },
                        OutputChunk::Log { level, message } => ExecuteOutput {
                            output: Some(proto::execute_output::Output::Log(proto::LogMessage {
                                level,
                                message,
                                timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
                            })),
                        },
                        OutputChunk::Done => break,
                    };

                    if stream_tx_clone.send(Ok(output)).await.is_err() {
                        break;
                    }
                }
            });

            // Execute the request
            let result = handler.handle_streaming(intent_request, ctx, output_tx).await;

            // Wait for forwarding to complete
            let _ = forward_handle.await;

            stats.requests_in_flight.fetch_sub(1, Ordering::Relaxed);

            match result {
                Ok(response) => {
                    stats.requests_succeeded.fetch_add(1, Ordering::Relaxed);
                    // Send final response
                    let _ = stream_tx
                        .send(Ok(ExecuteOutput {
                            output: Some(proto::execute_output::Output::Complete(
                                convert_intent_response_to_proto(response),
                            )),
                        }))
                        .await;
                }
                Err(e) => {
                    stats.requests_failed.fetch_add(1, Ordering::Relaxed);
                    let _ = stream_tx.send(Err(Status::internal(e.to_string()))).await;
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(stream_rx);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_capabilities(
        &self,
        _request: Request<ListCapabilitiesRequest>,
    ) -> Result<Response<ListCapabilitiesResponse>, Status> {
        let capabilities = self.handler.list_capabilities().await;

        let proto_caps: Vec<proto::CapabilityInfo> = capabilities
            .into_iter()
            .map(|c| proto::CapabilityInfo {
                name: c.name,
                description: c.description,
                version: c.version,
                param_schema_json: c.param_schema.map(|v| v.to_string()).unwrap_or_default(),
                requires_elevated: c.requires_elevated,
                supports_streaming: c.supports_streaming,
                tags: c.tags,
            })
            .collect();

        Ok(Response::new(ListCapabilitiesResponse {
            capabilities: proto_caps,
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let status = self.handler.health().await;

        let (healthy, status_str, details) = match status {
            HealthStatus::Healthy => (true, "healthy".to_string(), std::collections::HashMap::new()),
            HealthStatus::Degraded { reason } => {
                let mut d = std::collections::HashMap::new();
                d.insert("reason".to_string(), reason);
                (true, "degraded".to_string(), d)
            }
            HealthStatus::Unhealthy { reason } => {
                let mut d = std::collections::HashMap::new();
                d.insert("reason".to_string(), reason);
                (false, "unhealthy".to_string(), d)
            }
            HealthStatus::Starting => {
                (false, "starting".to_string(), std::collections::HashMap::new())
            }
            HealthStatus::Stopping => {
                (false, "stopping".to_string(), std::collections::HashMap::new())
            }
        };

        Ok(Response::new(HealthResponse {
            healthy,
            status: status_str,
            details,
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        // TODO: Implement sandbox listing
        Ok(Response::new(ListSandboxesResponse { sandboxes: vec![] }))
    }

    async fn create_sandbox(
        &self,
        _request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        // TODO: Implement sandbox creation
        Err(Status::unimplemented("Sandbox creation not yet implemented"))
    }

    async fn attach_sandbox(
        &self,
        _request: Request<AttachSandboxRequest>,
    ) -> Result<Response<AttachSandboxResponse>, Status> {
        // TODO: Implement sandbox attachment
        Err(Status::unimplemented(
            "Sandbox attachment not yet implemented",
        ))
    }

    async fn terminate_sandbox(
        &self,
        _request: Request<TerminateSandboxRequest>,
    ) -> Result<Response<TerminateSandboxResponse>, Status> {
        // TODO: Implement sandbox termination
        Err(Status::unimplemented(
            "Sandbox termination not yet implemented",
        ))
    }

    async fn get_sandbox_capabilities(
        &self,
        _request: Request<GetSandboxCapabilitiesRequest>,
    ) -> Result<Response<SandboxCapabilities>, Status> {
        // TODO: Implement sandbox capabilities retrieval
        Err(Status::unimplemented(
            "Get sandbox capabilities not yet implemented",
        ))
    }
}

/// Helper function to convert IntentResponse to proto ExecuteResponse
fn convert_intent_response_to_proto(resp: IntentResponse) -> ExecuteResponse {
    let status = match resp.status {
        IntentStatus::Ok => ExecutionStatus::Ok as i32,
        IntentStatus::Denied => ExecutionStatus::Denied as i32,
        IntentStatus::Error => ExecutionStatus::Error as i32,
        IntentStatus::Expired => ExecutionStatus::Expired as i32,
        IntentStatus::Cancelled => ExecutionStatus::Cancelled as i32,
        IntentStatus::Pending => ExecutionStatus::Pending as i32,
    };

    let result = resp.result.map(|r| ExecutionResult {
        exit_code: r.exit_code,
        stdout: r.stdout.clone().unwrap_or_default(),
        stdout_bytes: r.stdout_bytes.clone().unwrap_or_default(),
        stderr: r.stderr.unwrap_or_default(),
        output_json: r.output.map(|v| v.to_string()).unwrap_or_default(),
        artifacts: r
            .artifacts
            .into_iter()
            .map(|a| proto::Artifact {
                name: a.name,
                content_type: a.content_type,
                size: a.size,
                sha256: a.sha256,
                uri: a.uri.unwrap_or_default(),
                content: a.content.unwrap_or_default(),
            })
            .collect(),
        resource_usage: r.resource_usage.map(|u| proto::ResourceUsage {
            peak_memory_bytes: u.peak_memory_bytes,
            cpu_time_ms: u.cpu_time_ms,
            wall_time_ms: u.wall_time_ms,
            disk_write_bytes: u.disk_write_bytes,
            disk_read_bytes: u.disk_read_bytes,
            network_tx_bytes: u.network_tx_bytes,
            network_rx_bytes: u.network_rx_bytes,
        }),
    });

    let error = resp.error.map(|e| proto::ErrorDetails {
        code: e.code,
        message: e.message,
        details_json: e.details.map(|v| v.to_string()).unwrap_or_default(),
        retryable: e.retryable,
        retry_after_ms: e.retry_after_ms.unwrap_or(0),
    });

    let timing = Some(proto::ResponseTiming {
        received_at_ms: resp.timing.received_at_ms,
        started_at_ms: resp.timing.started_at_ms,
        completed_at_ms: resp.timing.completed_at_ms,
        queue_time_ms: resp.timing.queue_time_ms,
        setup_time_ms: resp.timing.setup_time_ms,
        exec_time_ms: resp.timing.exec_time_ms,
        total_time_ms: resp.timing.total_time_ms,
    });

    ExecuteResponse {
        request_id: resp.request_id.to_string(),
        status,
        code: resp.code,
        message: resp.message,
        result,
        error,
        timing,
        sandbox_info: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_config_default() {
        let config = GrpcConfig::default();
        assert_eq!(config.listen_address.port(), 9500);
        assert!(config.tls_cert_path.is_none());
    }

    #[test]
    fn test_adapter_creation() {
        let addr: SocketAddr = "127.0.0.1:9500".parse().unwrap();
        let adapter = GrpcAdapter::with_address(addr);
        assert_eq!(adapter.name(), "grpc");
        assert!(!adapter.is_running());
    }
}
