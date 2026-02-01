//! SQLite query validation utilities for secure database operations
//!
//! Provides comprehensive validation for SQLite queries to ensure read-only operations
//! and prevent SQL injection and dangerous query patterns.

use smith_protocol::ExecutionError;
use std::path::Path;

/// Validate SQL query to ensure it's read-only and secure
pub fn validate_read_only_query(query: &str) -> Result<(), ExecutionError> {
    let query_upper = query.to_uppercase().trim().to_string();

    // List of forbidden SQL keywords that indicate write operations
    let forbidden_keywords = [
        "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "REPLACE", "ATTACH",
        "DETACH", "VACUUM", "REINDEX", "PRAGMA",
    ];

    // Check for forbidden keywords at the start of statements
    for line in query_upper.split(';') {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        for forbidden in &forbidden_keywords {
            if trimmed.starts_with(forbidden) {
                return Err(ExecutionError {
                    code: "WRITE_OPERATION_FORBIDDEN".to_string(),
                    message: format!("Query contains forbidden operation: {}", forbidden),
                });
            }
        }

        // Additional checks for dangerous patterns
        if trimmed.contains("EXEC") || trimmed.contains("EXECUTE") {
            return Err(ExecutionError {
                code: "DYNAMIC_SQL_FORBIDDEN".to_string(),
                message: "Dynamic SQL execution is forbidden".to_string(),
            });
        }
    }

    // Ensure query starts with SELECT, WITH, or common table expressions
    let first_word = query_upper
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(';');

    if !matches!(first_word, "SELECT" | "WITH" | "VALUES") {
        return Err(ExecutionError {
            code: "INVALID_READ_ONLY_QUERY".to_string(),
            message: format!(
                "Query must start with SELECT, WITH, or VALUES, found: {}",
                first_word
            ),
        });
    }

    Ok(())
}

/// Validate database path for security
pub fn validate_database_path(path: &str) -> Result<(), ExecutionError> {
    // Validate database path
    if path.is_empty() {
        return Err(ExecutionError {
            code: "INVALID_PATH".to_string(),
            message: "Database path cannot be empty".to_string(),
        });
    }

    // Check for dangerous paths
    if path.contains("..") || path.starts_with('/') {
        return Err(ExecutionError {
            code: "UNSAFE_PATH".to_string(),
            message: "Database path contains unsafe components or is absolute".to_string(),
        });
    }

    Ok(())
}

/// Validate query limits
pub fn validate_query_limits(
    max_rows: Option<u32>,
    timeout_ms: Option<u32>,
    max_allowed_rows: u32,
    max_allowed_timeout: u32,
) -> Result<(), ExecutionError> {
    if let Some(max_rows) = max_rows {
        if max_rows > max_allowed_rows {
            return Err(ExecutionError {
                code: "LIMIT_EXCEEDED".to_string(),
                message: format!("max_rows {} exceeds limit {}", max_rows, max_allowed_rows),
            });
        }
    }

    if let Some(timeout_ms) = timeout_ms {
        if timeout_ms > max_allowed_timeout {
            return Err(ExecutionError {
                code: "TIMEOUT_EXCEEDED".to_string(),
                message: format!(
                    "timeout_ms {} exceeds limit {}",
                    timeout_ms, max_allowed_timeout
                ),
            });
        }
    }

    Ok(())
}

/// Check if database path is allowed according to execution scope
pub fn is_path_allowed(path: &str, allowed_paths: &[String]) -> bool {
    // If no specific paths are configured, allow any path within workdir
    if allowed_paths.is_empty() {
        return true;
    }

    // Check if path matches any allowed pattern
    for allowed in allowed_paths {
        if path.starts_with(allowed) || allowed == "*" {
            return true;
        }
    }

    false
}

/// Validate database file exists and size constraints
pub async fn validate_database_file(
    db_path: &Path,
    max_db_size: u64,
) -> Result<u64, ExecutionError> {
    use tokio::fs;

    // Check database exists
    if !db_path.exists() {
        return Err(ExecutionError {
            code: "DATABASE_NOT_FOUND".to_string(),
            message: format!("Database file does not exist: {}", db_path.display()),
        });
    }

    let metadata = fs::metadata(db_path).await.map_err(|e| ExecutionError {
        code: "DATABASE_METADATA_ERROR".to_string(),
        message: format!("Failed to get database metadata: {}", e),
    })?;

    let db_size = metadata.len();
    if db_size > max_db_size {
        return Err(ExecutionError {
            code: "DATABASE_TOO_LARGE".to_string(),
            message: format!("Database size {} exceeds limit {}", db_size, max_db_size),
        });
    }

    Ok(db_size)
}

/// Bind JSON parameters to SQLite query
pub fn bind_query_parameters<'a>(
    mut db_query: sqlx::query::Query<'a, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'a>>,
    params: &'a [serde_json::Value],
) -> sqlx::query::Query<'a, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'a>> {
    for param in params {
        db_query = match param {
            serde_json::Value::String(s) => db_query.bind(s),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    db_query.bind(i)
                } else if let Some(f) = n.as_f64() {
                    db_query.bind(f)
                } else {
                    db_query.bind(n.to_string())
                }
            }
            serde_json::Value::Bool(b) => db_query.bind(*b),
            serde_json::Value::Null => db_query.bind(None::<String>),
            _ => db_query.bind(param.to_string()),
        };
    }
    db_query
}

/// Convert SQLite row value to JSON
pub fn convert_row_value_to_json(row: &sqlx::sqlite::SqliteRow, column: &str) -> serde_json::Value {
    use sqlx::Row;

    match row.try_get::<Option<String>, _>(column) {
        Ok(Some(s)) => serde_json::Value::String(s),
        Ok(None) => serde_json::Value::Null,
        Err(_) => {
            // Try other types
            if let Ok(Some(i)) = row.try_get::<Option<i64>, _>(column) {
                serde_json::Value::Number(serde_json::Number::from(i))
            } else if let Ok(Some(f)) = row.try_get::<Option<f64>, _>(column) {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else if let Ok(Some(b)) = row.try_get::<Option<bool>, _>(column) {
                serde_json::Value::Bool(b)
            } else {
                serde_json::Value::Null
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_read_only_query() {
        // Valid read-only queries
        assert!(validate_read_only_query("SELECT * FROM users").is_ok());
        assert!(validate_read_only_query("SELECT name FROM users WHERE id = 1").is_ok());
        assert!(
            validate_read_only_query("WITH cte AS (SELECT * FROM users) SELECT * FROM cte").is_ok()
        );
        assert!(validate_read_only_query("VALUES (1, 'test'), (2, 'example')").is_ok());

        // Invalid write operations
        assert!(validate_read_only_query("INSERT INTO users VALUES (1, 'test')").is_err());
        assert!(validate_read_only_query("UPDATE users SET name = 'test'").is_err());
        assert!(validate_read_only_query("DELETE FROM users").is_err());
        assert!(validate_read_only_query("DROP TABLE users").is_err());
        assert!(validate_read_only_query("CREATE TABLE test (id INTEGER)").is_err());

        // Invalid starting keywords
        assert!(validate_read_only_query("PRAGMA table_info(users)").is_err());
        assert!(validate_read_only_query("ATTACH DATABASE 'other.db' AS other").is_err());

        // Dynamic SQL forbidden
        assert!(validate_read_only_query("SELECT * FROM users; EXEC sp_executesql").is_err());
        assert!(validate_read_only_query("SELECT EXECUTE('DROP TABLE users')").is_err());
    }

    #[test]
    fn test_validate_database_path() {
        // Valid paths
        assert!(validate_database_path("test.db").is_ok());
        assert!(validate_database_path("data/analytics.db").is_ok());

        // Invalid paths
        assert!(validate_database_path("").is_err());
        assert!(validate_database_path("../other.db").is_err());
        assert!(validate_database_path("/absolute/path.db").is_err());
        assert!(validate_database_path("some/../path.db").is_err());
    }

    #[test]
    fn test_validate_query_limits() {
        // Valid limits
        assert!(validate_query_limits(Some(100), Some(5000), 1000, 30000).is_ok());
        assert!(validate_query_limits(None, None, 1000, 30000).is_ok());

        // Exceeded limits
        assert!(validate_query_limits(Some(2000), Some(5000), 1000, 30000).is_err());
        assert!(validate_query_limits(Some(100), Some(50000), 1000, 30000).is_err());
    }

    #[test]
    fn test_is_path_allowed() {
        // Empty allowlist allows everything
        assert!(is_path_allowed("/any/path", &[]));

        // Specific allowlist
        let allowed = vec!["/allowed".to_string(), "/data".to_string()];
        assert!(is_path_allowed("/allowed/test.db", &allowed));
        assert!(is_path_allowed("/data/analytics.db", &allowed));
        assert!(!is_path_allowed("/forbidden/test.db", &allowed));

        // Wildcard allowlist
        let wildcard = vec!["*".to_string()];
        assert!(is_path_allowed("/any/path", &wildcard));
    }
}
