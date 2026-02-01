use anyhow::Result;
use async_trait::async_trait;
use serde_json::json;
use smith_protocol::{
    AllowlistHit, CapabilitySpec, ExecutionError, ExecutionStatus, Intent, ResourceRequirements,
};
use sqlx::{Column, Row};
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::capabilities::sqlite_validation::{
    self, bind_query_parameters, convert_row_value_to_json,
};
use crate::capability::{Capability, CapabilityResult, ExecCtx, ExecutionMetadata};

/// SqliteQueryV1 capability for read-only SQLite database querying
pub struct SqliteQueryV1Capability {
    /// Maximum rows to return per query (default 1000)
    max_rows: u32,
    /// Maximum query timeout (default 30 seconds)
    max_timeout_ms: u32,
    /// Maximum database file size (default 1GB)
    max_db_size: u64,
}

/// Query result row
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryRow {
    /// Column values as key-value pairs
    pub values: std::collections::HashMap<String, serde_json::Value>,
}

/// Query execution result
#[derive(Debug, Clone, serde::Serialize)]
pub struct QueryResult {
    /// Result rows
    pub rows: Vec<QueryRow>,
    /// Number of rows returned
    pub row_count: usize,
    /// Column names in order
    pub columns: Vec<String>,
    /// Query execution time in milliseconds
    pub execution_time_ms: u64,
    /// Whether result was truncated due to max_rows limit
    pub truncated: bool,
}

impl SqliteQueryV1Capability {
    pub fn new() -> Self {
        Self {
            max_rows: 1000,
            max_timeout_ms: 30000,           // 30 seconds
            max_db_size: 1024 * 1024 * 1024, // 1GB
        }
    }

    /// Create with custom limits
    pub fn with_limits(max_rows: u32, max_timeout_ms: u32, max_db_size: u64) -> Self {
        Self {
            max_rows,
            max_timeout_ms,
            max_db_size,
        }
    }

    /// Execute read-only query against SQLite database
    async fn execute_query(
        &self,
        db_path: &Path,
        query: &str,
        params: &[serde_json::Value],
        max_rows: u32,
        timeout_ms: u32,
    ) -> Result<QueryResult> {
        let start_time = std::time::Instant::now();

        // Open database in read-only mode
        let db_url = format!("sqlite://{}?mode=ro", db_path.to_string_lossy());

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(timeout_ms as u64))
            .connect(&db_url)
            .await?;

        // Prepare the query and bind parameters
        let db_query = sqlx::query(query);
        let db_query = bind_query_parameters(db_query, params);

        // Execute with timeout
        let timeout = Duration::from_millis(timeout_ms as u64);
        let rows_result = tokio::time::timeout(timeout, db_query.fetch_all(&pool)).await;

        let rows = match rows_result {
            Ok(Ok(rows)) => rows,
            Ok(Err(e)) => return Err(anyhow::anyhow!("Query execution failed: {}", e)),
            Err(_) => return Err(anyhow::anyhow!("Query timed out after {} ms", timeout_ms)),
        };

        // Process results
        let mut result_rows = Vec::new();
        let mut columns: Vec<String> = Vec::new();
        let mut truncated = false;

        if let Some(first_row) = rows.first() {
            // Extract column names from the first row
            columns = first_row
                .columns()
                .iter()
                .map(|col| col.name().to_string())
                .collect();
        }

        for (i, row) in rows.iter().enumerate() {
            if i as u32 >= max_rows {
                truncated = true;
                break;
            }

            let mut row_values = std::collections::HashMap::new();

            for column in &columns {
                let value = convert_row_value_to_json(row, column);
                row_values.insert(column.clone(), value);
            }

            result_rows.push(QueryRow { values: row_values });
        }

        let execution_time = start_time.elapsed();
        let row_count = result_rows.len();

        Ok(QueryResult {
            rows: result_rows,
            row_count,
            columns,
            execution_time_ms: execution_time.as_millis() as u64,
            truncated,
        })
    }
}

#[async_trait]
impl Capability for SqliteQueryV1Capability {
    fn name(&self) -> &'static str {
        "sqlite.query.v1"
    }

    fn validate(&self, intent: &Intent) -> Result<(), ExecutionError> {
        // Validate that this is a sqlite.query.v1 intent
        if intent.capability != smith_protocol::Capability::SqliteQueryV1 {
            return Err(ExecutionError {
                code: "CAPABILITY_MISMATCH".to_string(),
                message: format!("Expected sqlite.query.v1, got {}", intent.capability),
            });
        }

        // Parse and validate parameters
        let params: smith_protocol::params::SqliteQueryV1 =
            serde_json::from_value(intent.params.clone()).map_err(|e| ExecutionError {
                code: "INVALID_PARAMS".to_string(),
                message: format!("Failed to parse sqlite.query.v1 parameters: {}", e),
            })?;

        // Validate database path
        sqlite_validation::validate_database_path(&params.database_path)?;

        // Validate query
        if params.query.trim().is_empty() {
            return Err(ExecutionError {
                code: "EMPTY_QUERY".to_string(),
                message: "SQL query cannot be empty".to_string(),
            });
        }

        // Validate that query is read-only
        sqlite_validation::validate_read_only_query(&params.query)?;

        // Validate limits
        sqlite_validation::validate_query_limits(
            params.max_rows,
            params.timeout_ms,
            self.max_rows,
            self.max_timeout_ms,
        )?;

        debug!(
            "sqlite.query.v1 parameters validated successfully for database: {}",
            params.database_path
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

        info!("Executing sqlite.query.v1 for intent: {}", intent.id);

        // In strict security mode, check if database operations are allowed
        if ctx.sandbox.mode == smith_protocol::SandboxMode::Full {
            let db_allowed = ctx
                .scope
                .custom
                .get("allow_database")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if !db_allowed {
                return Err(ExecutionError {
                    code: "DATABASE_DENIED_STRICT_MODE".to_string(),
                    message: "Database operations denied in strict security mode".to_string(),
                });
            }
        }

        // Parse parameters
        let params: smith_protocol::params::SqliteQueryV1 = serde_json::from_value(intent.params)
            .map_err(|e| ExecutionError {
            code: "PARAM_PARSE_ERROR".to_string(),
            message: format!("Failed to parse parameters: {}", e),
        })?;

        // Resolve database path within workdir
        let db_path = ctx.workdir.join(&params.database_path);

        // Check if path is allowed
        let path_str = db_path.to_string_lossy().to_string();
        if !sqlite_validation::is_path_allowed(&path_str, &ctx.scope.paths) {
            return Err(ExecutionError {
                code: "PATH_DENIED".to_string(),
                message: format!(
                    "Database path not in allowed list: {}",
                    params.database_path
                ),
            });
        }

        debug!("Querying database: {:?}", db_path);

        // Check database exists and size
        let db_size = sqlite_validation::validate_database_file(&db_path, self.max_db_size).await?;

        // Track allowlist hit
        let _allowlist_hit = AllowlistHit {
            resource_type: "database".to_string(),
            resource_id: path_str.clone(),
            operation: "query".to_string(),
            timestamp_ns: start_ns,
        };

        // Execute query
        let query_params = params.params.unwrap_or_default();
        let max_rows = params.max_rows.unwrap_or(self.max_rows).min(self.max_rows);
        let timeout_ms = params.timeout_ms.unwrap_or(30000).min(self.max_timeout_ms);

        let query_result = self
            .execute_query(&db_path, &params.query, &query_params, max_rows, timeout_ms)
            .await;

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        match query_result {
            Ok(result) => {
                info!(
                    "Successfully executed query on {} returning {} rows ({}ms)",
                    params.database_path, result.row_count, result.execution_time_ms
                );

                let output = json!({
                    "database_path": params.database_path,
                    "query": params.query,
                    "row_count": result.row_count,
                    "columns": result.columns,
                    "rows": result.rows,
                    "execution_time_ms": result.execution_time_ms,
                    "truncated": result.truncated,
                    "max_rows_limit": max_rows,
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
                        artifacts: vec![],
                    },
                    resource_usage: smith_protocol::ResourceUsage {
                        peak_memory_kb: 2048, // Database operations may need more memory
                        cpu_time_ms: duration_ms as u32,
                        wall_time_ms: duration_ms as u32,
                        fd_count: 1,
                        disk_read_bytes: db_size, // Approximate
                        disk_write_bytes: 0,      // Read-only
                        network_tx_bytes: 0,
                        network_rx_bytes: 0,
                    },
                })
            }
            Err(e) => {
                warn!("Failed to execute query on {}: {}", params.database_path, e);

                Err(ExecutionError {
                    code: "QUERY_EXECUTION_ERROR".to_string(),
                    message: format!("Failed to execute query: {}", e),
                })
            }
        }
    }

    fn describe(&self) -> CapabilitySpec {
        CapabilitySpec {
            name: self.name().to_string(),
            description:
                "Execute read-only SQL queries against SQLite databases with safety controls"
                    .to_string(),
            params_schema: json!({
                "type": "object",
                "properties": {
                    "database_path": {
                        "type": "string",
                        "description": "Relative path to the SQLite database file",
                        "example": "data/analytics.db"
                    },
                    "query": {
                        "type": "string",
                        "description": "SQL SELECT query to execute (read-only)",
                        "example": "SELECT * FROM users WHERE active = 1 ORDER BY created_at DESC"
                    },
                    "params": {
                        "type": "array",
                        "items": {},
                        "description": "Parameters for prepared statements (optional)",
                        "example": ["active_user", 100]
                    },
                    "max_rows": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1000,
                        "description": "Maximum rows to return (default: 1000)",
                        "example": 50
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 1000,
                        "maximum": 30000,
                        "description": "Query timeout in milliseconds (default: 30000)",
                        "example": 10000
                    }
                },
                "required": ["database_path", "query"],
                "additionalProperties": false
            }),
            example_params: json!({
                "database_path": "analytics/events.db",
                "query": "SELECT event_type, COUNT(*) as count FROM events WHERE date >= ? GROUP BY event_type ORDER BY count DESC LIMIT ?",
                "params": ["2024-01-01", 10],
                "max_rows": 100
            }),
            resource_requirements: ResourceRequirements {
                cpu_ms_typical: 100,
                memory_kb_max: 4096,
                network_access: false,
                filesystem_access: true,
                external_commands: false,
            },
            security_notes: vec![
                "Database files must be within the execution workdir".to_string(),
                "Only SELECT, WITH, and VALUES queries are allowed".to_string(),
                "Write operations (INSERT, UPDATE, DELETE, etc.) are forbidden".to_string(),
                "Database opens in read-only mode preventing modifications".to_string(),
                "Query timeouts prevent long-running operations".to_string(),
                format!("Maximum {} rows returned per query", self.max_rows),
                format!("Maximum database file size: {} bytes", self.max_db_size),
                "Parameterized queries prevent SQL injection".to_string(),
                "Database operations denied in strict security mode unless explicitly allowed"
                    .to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smith_protocol::Capability as ProtoCapability;

    // ==================== Constructor Tests ====================

    #[test]
    fn test_new_default_limits() {
        let cap = SqliteQueryV1Capability::new();
        assert_eq!(cap.max_rows, 1000);
        assert_eq!(cap.max_timeout_ms, 30000);
        assert_eq!(cap.max_db_size, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_with_limits() {
        let cap = SqliteQueryV1Capability::with_limits(500, 15000, 512 * 1024 * 1024);
        assert_eq!(cap.max_rows, 500);
        assert_eq!(cap.max_timeout_ms, 15000);
        assert_eq!(cap.max_db_size, 512 * 1024 * 1024);
    }

    // ==================== Capability Trait Tests ====================

    #[test]
    fn test_name() {
        let cap = SqliteQueryV1Capability::new();
        assert_eq!(cap.name(), "sqlite.query.v1");
    }

    #[test]
    fn test_describe() {
        let cap = SqliteQueryV1Capability::new();
        let spec = cap.describe();

        assert_eq!(spec.name, "sqlite.query.v1");
        assert!(spec.description.contains("SQLite"));
        assert!(spec.description.contains("read-only"));

        // Check params schema
        let schema = spec.params_schema.as_object().unwrap();
        let props = schema.get("properties").unwrap().as_object().unwrap();
        assert!(props.contains_key("database_path"));
        assert!(props.contains_key("query"));
        assert!(props.contains_key("params"));
        assert!(props.contains_key("max_rows"));
        assert!(props.contains_key("timeout_ms"));

        // Check required fields
        let required = schema.get("required").unwrap().as_array().unwrap();
        assert!(required.contains(&json!("database_path")));
        assert!(required.contains(&json!("query")));

        // Check resource requirements
        assert!(!spec.resource_requirements.network_access);
        assert!(spec.resource_requirements.filesystem_access);
        assert!(!spec.resource_requirements.external_commands);

        // Check security notes
        assert!(!spec.security_notes.is_empty());
        assert!(spec.security_notes.iter().any(|n| n.contains("read-only")));
    }

    #[test]
    fn test_describe_custom_limits() {
        let cap = SqliteQueryV1Capability::with_limits(100, 5000, 100 * 1024 * 1024);
        let spec = cap.describe();

        // Security notes should reflect custom limits
        assert!(spec.security_notes.iter().any(|n| n.contains("100")));
    }

    // ==================== Validation Tests ====================

    #[tokio::test]
    async fn test_sqlite_query_v1_validation() {
        let capability = SqliteQueryV1Capability::new();

        // Valid intent
        let valid_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "SELECT * FROM users"
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&valid_intent).is_ok());

        // Invalid intent - empty database path
        let invalid_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "",
                "query": "SELECT * FROM users"
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(capability.validate(&invalid_intent).is_err());
    }

    #[test]
    fn test_validate_empty_query() {
        let cap = SqliteQueryV1Capability::new();
        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": ""
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&intent);
        assert!(result.is_err());
        assert!(result.unwrap_err().code.contains("EMPTY_QUERY"));
    }

    #[test]
    fn test_validate_whitespace_query() {
        let cap = SqliteQueryV1Capability::new();
        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "   \t\n  "
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&intent);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_write_query_rejected() {
        let cap = SqliteQueryV1Capability::new();

        // INSERT should be rejected
        let insert_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "INSERT INTO users (name) VALUES ('test')"
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&insert_intent);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_update_query_rejected() {
        let cap = SqliteQueryV1Capability::new();

        let update_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "UPDATE users SET name = 'test'"
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&update_intent);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_query_rejected() {
        let cap = SqliteQueryV1Capability::new();

        let delete_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "DELETE FROM users"
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&delete_intent);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_drop_query_rejected() {
        let cap = SqliteQueryV1Capability::new();

        let drop_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "DROP TABLE users"
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&drop_intent);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_capability_mismatch() {
        let cap = SqliteQueryV1Capability::new();

        let wrong_capability_intent = Intent::new(
            ProtoCapability::FsReadV1,  // Wrong capability
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "SELECT * FROM users"
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&wrong_capability_intent);
        assert!(result.is_err());
        assert!(result.unwrap_err().code.contains("CAPABILITY_MISMATCH"));
    }

    #[test]
    fn test_validate_invalid_params() {
        let cap = SqliteQueryV1Capability::new();

        let invalid_params_intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({"invalid": "params"}),  // Missing required fields
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&invalid_params_intent);
        assert!(result.is_err());
        assert!(result.unwrap_err().code.contains("INVALID_PARAMS"));
    }

    #[test]
    fn test_validate_with_custom_max_rows() {
        let cap = SqliteQueryV1Capability::with_limits(50, 30000, 1024 * 1024 * 1024);

        // max_rows above limit should fail
        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "SELECT * FROM users",
                "max_rows": 100  // Above limit of 50
            }),
            30000,
            "test-signer".to_string(),
        );

        let result = cap.validate(&intent);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_select_with_subquery() {
        let cap = SqliteQueryV1Capability::new();

        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)"
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(cap.validate(&intent).is_ok());
    }

    #[test]
    fn test_validate_select_with_cte() {
        let cap = SqliteQueryV1Capability::new();

        let intent = Intent::new(
            ProtoCapability::SqliteQueryV1,
            "test".to_string(),
            json!({
                "database_path": "test.db",
                "query": "WITH active_users AS (SELECT * FROM users WHERE active = 1) SELECT * FROM active_users"
            }),
            30000,
            "test-signer".to_string(),
        );

        assert!(cap.validate(&intent).is_ok());
    }

    // ==================== QueryRow Tests ====================

    #[test]
    fn test_query_row_serialize() {
        let mut values = std::collections::HashMap::new();
        values.insert("id".to_string(), json!(1));
        values.insert("name".to_string(), json!("Alice"));

        let row = QueryRow { values };

        let serialized = serde_json::to_string(&row).unwrap();
        assert!(serialized.contains("\"id\":1"));
        assert!(serialized.contains("\"name\":\"Alice\""));
    }

    // ==================== QueryResult Tests ====================

    #[test]
    fn test_query_result_serialize() {
        let mut values = std::collections::HashMap::new();
        values.insert("id".to_string(), json!(1));

        let result = QueryResult {
            rows: vec![QueryRow { values }],
            row_count: 1,
            columns: vec!["id".to_string()],
            execution_time_ms: 50,
            truncated: false,
        };

        let serialized = serde_json::to_string(&result).unwrap();
        assert!(serialized.contains("\"row_count\":1"));
        assert!(serialized.contains("\"execution_time_ms\":50"));
        assert!(serialized.contains("\"truncated\":false"));
    }

    #[test]
    fn test_query_result_truncated() {
        let result = QueryResult {
            rows: vec![],
            row_count: 0,
            columns: vec!["col1".to_string()],
            execution_time_ms: 100,
            truncated: true,
        };

        assert!(result.truncated);
        assert_eq!(result.row_count, 0);
    }

    #[test]
    fn test_query_result_multiple_columns() {
        let result = QueryResult {
            rows: vec![],
            row_count: 0,
            columns: vec!["id".to_string(), "name".to_string(), "email".to_string()],
            execution_time_ms: 10,
            truncated: false,
        };

        assert_eq!(result.columns.len(), 3);
        assert!(result.columns.contains(&"email".to_string()));
    }
}
