//! Statistical analysis for benchmark data
//!
//! Provides regression detection, statistical calculations, and performance
//! analysis utilities for benchmark reporting.

use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

/// Historical benchmark data point
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BenchmarkDataPoint {
    /// Timestamp when benchmark was recorded
    pub timestamp: DateTime<Utc>,
    /// Performance metrics
    pub metrics: HashMap<String, f64>,
    /// Benchmark metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Intent ID that recorded this benchmark
    pub intent_id: String,
}

/// Performance regression analysis results
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegressionAnalysis {
    /// Whether a regression was detected
    pub regression_detected: bool,
    /// Metrics that show regression
    pub regressed_metrics: Vec<String>,
    /// Percentage change for regressed metrics
    pub regression_percentages: HashMap<String, f64>,
    /// Historical baseline values
    pub baseline_values: HashMap<String, f64>,
    /// Current values
    pub current_values: HashMap<String, f64>,
}

/// Statistical summary of benchmark data
#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkStatistics {
    /// Mean values for each metric
    pub mean_values: HashMap<String, f64>,
    /// Standard deviations for each metric
    pub std_deviations: HashMap<String, f64>,
    /// Minimum values for each metric
    pub min_values: HashMap<String, f64>,
    /// Maximum values for each metric
    pub max_values: HashMap<String, f64>,
    /// Number of data points in the sample
    pub sample_size: usize,
}

/// Analyzes performance regression by comparing current metrics against historical data
pub fn analyze_regression(
    current_metrics: &HashMap<String, f64>,
    historical_data: &[BenchmarkDataPoint],
) -> RegressionAnalysis {
    if historical_data.len() < 5 {
        // Need at least 5 data points for meaningful analysis
        return RegressionAnalysis {
            regression_detected: false,
            regressed_metrics: vec![],
            regression_percentages: HashMap::new(),
            baseline_values: HashMap::new(),
            current_values: current_metrics.clone(),
        };
    }

    let mut regressed_metrics = Vec::new();
    let mut regression_percentages = HashMap::new();
    let mut baseline_values = HashMap::new();

    // Calculate baseline from recent historical data (last 10 points or all if less)
    let baseline_data: Vec<_> = historical_data.iter().take(10).collect();

    for (metric_name, &current_value) in current_metrics {
        // Calculate historical mean for this metric
        let historical_values: Vec<f64> = baseline_data
            .iter()
            .filter_map(|point| point.metrics.get(metric_name).copied())
            .collect();

        if historical_values.is_empty() {
            continue;
        }

        let historical_mean = calculate_mean(&historical_values);
        baseline_values.insert(metric_name.clone(), historical_mean);

        // Calculate standard deviation
        let std_dev = calculate_std_deviation(&historical_values, historical_mean);

        // Check for significant regression (current value worse than 2 standard deviations)
        let _threshold = historical_mean + (2.0 * std_dev);

        // Determine if current value represents a regression based on metric type
        let is_regression =
            is_performance_regression(metric_name, current_value, historical_mean, std_dev);

        if is_regression {
            regressed_metrics.push(metric_name.clone());
            let percentage_change = calculate_percentage_change(current_value, historical_mean);
            regression_percentages.insert(metric_name.clone(), percentage_change);
        }
    }

    RegressionAnalysis {
        regression_detected: !regressed_metrics.is_empty(),
        regressed_metrics,
        regression_percentages,
        baseline_values,
        current_values: current_metrics.clone(),
    }
}

/// Calculates comprehensive statistics for historical benchmark data
pub fn calculate_statistics(historical_data: &[BenchmarkDataPoint]) -> BenchmarkStatistics {
    let mut mean_values = HashMap::new();
    let mut std_deviations = HashMap::new();
    let mut min_values = HashMap::new();
    let mut max_values = HashMap::new();

    if historical_data.is_empty() {
        return BenchmarkStatistics {
            mean_values,
            std_deviations,
            min_values,
            max_values,
            sample_size: 0,
        };
    }

    // Collect all metric names
    let all_metrics = collect_metric_names(historical_data);

    // Calculate statistics for each metric
    for metric_name in all_metrics {
        let values: Vec<f64> = historical_data
            .iter()
            .filter_map(|point| point.metrics.get(&metric_name).copied())
            .collect();

        if values.is_empty() {
            continue;
        }

        let mean = calculate_mean(&values);
        mean_values.insert(metric_name.clone(), mean);

        let std_dev = calculate_std_deviation(&values, mean);
        std_deviations.insert(metric_name.clone(), std_dev);

        if let Some(&min_val) = values.iter().min_by(|a, b| a.partial_cmp(b).unwrap()) {
            min_values.insert(metric_name.clone(), min_val);
        }

        if let Some(&max_val) = values.iter().max_by(|a, b| a.partial_cmp(b).unwrap()) {
            max_values.insert(metric_name.clone(), max_val);
        }
    }

    BenchmarkStatistics {
        mean_values,
        std_deviations,
        min_values,
        max_values,
        sample_size: historical_data.len(),
    }
}

/// Determines if a metric value represents a performance regression
fn is_performance_regression(
    metric_name: &str,
    current_value: f64,
    historical_mean: f64,
    std_dev: f64,
) -> bool {
    let threshold_high = historical_mean + (2.0 * std_dev);
    let threshold_low = historical_mean - (2.0 * std_dev);

    // For performance metrics, higher values usually indicate regression
    // This is a simplified heuristic - in practice, you might want to configure
    // whether higher or lower values indicate regression per metric
    if is_time_based_metric(metric_name) {
        // Higher is worse for time-based metrics
        current_value > threshold_high
    } else if is_throughput_metric(metric_name) {
        // Lower is worse for throughput metrics
        current_value < threshold_low
    } else {
        // Default: higher is worse
        current_value > threshold_high
    }
}

/// Checks if a metric is time-based (where higher values are worse)
fn is_time_based_metric(metric_name: &str) -> bool {
    metric_name.contains("time")
        || metric_name.contains("duration")
        || metric_name.contains("latency")
}

/// Checks if a metric is throughput-based (where lower values are worse)
fn is_throughput_metric(metric_name: &str) -> bool {
    metric_name.contains("throughput") || metric_name.contains("rps") || metric_name.contains("ops")
}

/// Calculates the mean of a set of values
fn calculate_mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

/// Calculates standard deviation given values and their mean
fn calculate_std_deviation(values: &[f64], mean: f64) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }

    let variance = values
        .iter()
        .map(|&value| (value - mean).powi(2))
        .sum::<f64>()
        / (values.len() - 1) as f64; // Sample standard deviation (n-1)

    variance.sqrt()
}

/// Calculates percentage change between current and historical values
fn calculate_percentage_change(current_value: f64, historical_mean: f64) -> f64 {
    if historical_mean == 0.0 {
        return 0.0;
    }
    ((current_value - historical_mean) / historical_mean) * 100.0
}

/// Collects all unique metric names from historical data
fn collect_metric_names(historical_data: &[BenchmarkDataPoint]) -> HashSet<String> {
    let mut all_metrics = HashSet::new();
    for point in historical_data {
        for metric_name in point.metrics.keys() {
            all_metrics.insert(metric_name.clone());
        }
    }
    all_metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_data_point(
        metrics: HashMap<String, f64>,
        intent_id: &str,
    ) -> BenchmarkDataPoint {
        BenchmarkDataPoint {
            timestamp: Utc::now(),
            metrics,
            metadata: HashMap::new(),
            intent_id: intent_id.to_string(),
        }
    }

    #[test]
    fn test_calculate_mean() {
        assert_eq!(calculate_mean(&[1.0, 2.0, 3.0, 4.0, 5.0]), 3.0);
        assert_eq!(calculate_mean(&[]), 0.0);
        assert_eq!(calculate_mean(&[42.0]), 42.0);
    }

    #[test]
    fn test_calculate_std_deviation() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let mean = calculate_mean(&values);
        let std_dev = calculate_std_deviation(&values, mean);
        // Standard deviation of [1,2,3,4,5] is approximately 1.58
        assert!((std_dev - 1.58).abs() < 0.01);
    }

    #[test]
    fn test_calculate_std_deviation_empty() {
        assert_eq!(calculate_std_deviation(&[], 0.0), 0.0);
    }

    #[test]
    fn test_calculate_std_deviation_single_value() {
        assert_eq!(calculate_std_deviation(&[42.0], 42.0), 0.0);
    }

    #[test]
    fn test_metric_type_detection() {
        assert!(is_time_based_metric("response_time"));
        assert!(is_time_based_metric("duration_ms"));
        assert!(is_time_based_metric("latency"));

        assert!(is_throughput_metric("throughput"));
        assert!(is_throughput_metric("ops_per_sec"));
        assert!(is_throughput_metric("rps"));

        assert!(!is_time_based_metric("memory_usage"));
        assert!(!is_throughput_metric("cpu_usage"));
    }

    #[test]
    fn test_calculate_percentage_change() {
        // Positive change
        assert!((calculate_percentage_change(110.0, 100.0) - 10.0).abs() < 0.001);

        // Negative change
        assert!((calculate_percentage_change(90.0, 100.0) - (-10.0)).abs() < 0.001);

        // No change
        assert!((calculate_percentage_change(100.0, 100.0) - 0.0).abs() < 0.001);

        // Zero baseline returns 0
        assert_eq!(calculate_percentage_change(50.0, 0.0), 0.0);
    }

    #[test]
    fn test_collect_metric_names() {
        let mut metrics1 = HashMap::new();
        metrics1.insert("latency".to_string(), 100.0);
        metrics1.insert("throughput".to_string(), 1000.0);

        let mut metrics2 = HashMap::new();
        metrics2.insert("latency".to_string(), 105.0);
        metrics2.insert("memory".to_string(), 512.0);

        let data = vec![
            create_test_data_point(metrics1, "intent-1"),
            create_test_data_point(metrics2, "intent-2"),
        ];

        let names = collect_metric_names(&data);
        assert_eq!(names.len(), 3);
        assert!(names.contains("latency"));
        assert!(names.contains("throughput"));
        assert!(names.contains("memory"));
    }

    #[test]
    fn test_collect_metric_names_empty() {
        let names = collect_metric_names(&[]);
        assert!(names.is_empty());
    }

    #[test]
    fn test_analyze_regression_insufficient_data() {
        let mut current = HashMap::new();
        current.insert("latency".to_string(), 100.0);

        // Only 4 data points - not enough for analysis
        let historical: Vec<BenchmarkDataPoint> = (0..4)
            .map(|i| {
                let mut m = HashMap::new();
                m.insert("latency".to_string(), 95.0 + i as f64);
                create_test_data_point(m, &format!("intent-{}", i))
            })
            .collect();

        let result = analyze_regression(&current, &historical);
        assert!(!result.regression_detected);
        assert!(result.regressed_metrics.is_empty());
    }

    #[test]
    fn test_analyze_regression_with_regression() {
        let mut current = HashMap::new();
        // Current latency is significantly higher (worse) than historical
        current.insert("response_time".to_string(), 200.0);

        // Historical data with stable latency around 100
        let historical: Vec<BenchmarkDataPoint> = (0..10)
            .map(|i| {
                let mut m = HashMap::new();
                m.insert("response_time".to_string(), 100.0 + (i % 3) as f64); // Small variance
                create_test_data_point(m, &format!("intent-{}", i))
            })
            .collect();

        let result = analyze_regression(&current, &historical);
        assert!(result.regression_detected);
        assert!(result.regressed_metrics.contains(&"response_time".to_string()));
        assert!(result.regression_percentages.contains_key("response_time"));
    }

    #[test]
    fn test_analyze_regression_throughput_drop() {
        let mut current = HashMap::new();
        // Current throughput is significantly lower (worse) than historical
        current.insert("rps".to_string(), 50.0);

        // Historical data with stable throughput around 100
        let historical: Vec<BenchmarkDataPoint> = (0..10)
            .map(|i| {
                let mut m = HashMap::new();
                m.insert("rps".to_string(), 100.0 + (i % 3) as f64);
                create_test_data_point(m, &format!("intent-{}", i))
            })
            .collect();

        let result = analyze_regression(&current, &historical);
        assert!(result.regression_detected);
        assert!(result.regressed_metrics.contains(&"rps".to_string()));
    }

    #[test]
    fn test_analyze_regression_no_regression() {
        let mut current = HashMap::new();
        current.insert("latency".to_string(), 101.0);

        let historical: Vec<BenchmarkDataPoint> = (0..10)
            .map(|i| {
                let mut m = HashMap::new();
                m.insert("latency".to_string(), 100.0 + (i % 5) as f64);
                create_test_data_point(m, &format!("intent-{}", i))
            })
            .collect();

        let result = analyze_regression(&current, &historical);
        assert!(!result.regression_detected);
    }

    #[test]
    fn test_calculate_statistics_empty() {
        let stats = calculate_statistics(&[]);
        assert_eq!(stats.sample_size, 0);
        assert!(stats.mean_values.is_empty());
        assert!(stats.std_deviations.is_empty());
    }

    #[test]
    fn test_calculate_statistics() {
        let historical: Vec<BenchmarkDataPoint> = (0..5)
            .map(|i| {
                let mut m = HashMap::new();
                m.insert("latency".to_string(), (i + 1) as f64 * 10.0); // 10, 20, 30, 40, 50
                create_test_data_point(m, &format!("intent-{}", i))
            })
            .collect();

        let stats = calculate_statistics(&historical);
        assert_eq!(stats.sample_size, 5);

        let mean = stats.mean_values.get("latency").unwrap();
        assert!((mean - 30.0).abs() < 0.001); // (10+20+30+40+50)/5 = 30

        let min = stats.min_values.get("latency").unwrap();
        assert!((min - 10.0).abs() < 0.001);

        let max = stats.max_values.get("latency").unwrap();
        assert!((max - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_is_performance_regression_time_based() {
        // For time-based metrics, higher is worse
        assert!(is_performance_regression("response_time", 150.0, 100.0, 10.0)); // Way above threshold
        assert!(!is_performance_regression("response_time", 105.0, 100.0, 10.0)); // Within threshold
    }

    #[test]
    fn test_is_performance_regression_throughput() {
        // For throughput metrics, lower is worse
        assert!(is_performance_regression("ops_per_sec", 70.0, 100.0, 10.0)); // Way below threshold
        assert!(!is_performance_regression("ops_per_sec", 95.0, 100.0, 10.0)); // Within threshold
    }

    #[test]
    fn test_is_performance_regression_default() {
        // For unknown metrics, default to higher is worse
        assert!(is_performance_regression("memory_usage", 150.0, 100.0, 10.0));
        assert!(!is_performance_regression("memory_usage", 105.0, 100.0, 10.0));
    }
}
