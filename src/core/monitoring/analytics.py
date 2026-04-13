"""
Performance Analytics Engine

Historical performance analysis, trend analysis, capacity forecasting,
performance regression detection, and automated performance reporting.
This implements Phase 8.5: Performance Analytics & Reporting.
"""

import asyncio
import logging
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import aiosqlite
import uuid
import statistics
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.linear_model import LinearRegression, Ridge
    from sklearn.ensemble import RandomForestRegressor
    from sklearn.preprocessing import StandardScaler, PolynomialFeatures
    from sklearn.metrics import mean_squared_error, r2_score
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available, using simplified analytics")

from .metrics_collector import MetricType, MetricScope
from .tracing import get_tracer

logger = logging.getLogger(__name__)


class AnalyticsType(Enum):
    """Types of performance analytics."""
    TREND_ANALYSIS = "trend_analysis"
    CAPACITY_FORECAST = "capacity_forecast"
    REGRESSION_DETECTION = "regression_detection"
    ANOMALY_PATTERN = "anomaly_pattern"
    PERFORMANCE_BASELINE = "performance_baseline"
    RESOURCE_UTILIZATION = "resource_utilization"
    SLA_COMPLIANCE = "sla_compliance"


class TrendDirection(Enum):
    """Trend direction enumeration."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


class ForecastConfidence(Enum):
    """Forecast confidence levels."""
    HIGH = "high"      # > 90% accuracy
    MEDIUM = "medium"  # 70-90% accuracy
    LOW = "low"        # 50-70% accuracy
    UNRELIABLE = "unreliable"  # < 50% accuracy


@dataclass
class TrendAnalysis:
    """Trend analysis results."""
    metric_name: str
    time_period: str
    direction: TrendDirection
    slope: float
    correlation_coefficient: float
    p_value: float
    confidence: float
    start_value: float
    end_value: float
    change_percentage: float
    volatility: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric_name': self.metric_name,
            'time_period': self.time_period,
            'direction': self.direction.value,
            'slope': self.slope,
            'correlation_coefficient': self.correlation_coefficient,
            'p_value': self.p_value,
            'confidence': self.confidence,
            'start_value': self.start_value,
            'end_value': self.end_value,
            'change_percentage': self.change_percentage,
            'volatility': self.volatility,
            'metadata': self.metadata
        }


@dataclass
class CapacityForecast:
    """Capacity forecasting results."""
    metric_name: str
    resource_type: str
    current_value: float
    predicted_value: float
    forecast_date: datetime
    confidence_level: ForecastConfidence
    confidence_interval: Tuple[float, float]
    time_to_threshold: Optional[timedelta]
    threshold_value: Optional[float]
    model_accuracy: float
    seasonal_component: Optional[float] = None
    trend_component: Optional[float] = None
    residual_component: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric_name': self.metric_name,
            'resource_type': self.resource_type,
            'current_value': self.current_value,
            'predicted_value': self.predicted_value,
            'forecast_date': self.forecast_date.isoformat(),
            'confidence_level': self.confidence_level.value,
            'confidence_interval': self.confidence_interval,
            'time_to_threshold': self.time_to_threshold.total_seconds() if self.time_to_threshold else None,
            'threshold_value': self.threshold_value,
            'model_accuracy': self.model_accuracy,
            'seasonal_component': self.seasonal_component,
            'trend_component': self.trend_component,
            'residual_component': self.residual_component
        }


@dataclass
class PerformanceBaseline:
    """Performance baseline definition."""
    metric_name: str
    baseline_value: float
    acceptable_range: Tuple[float, float]
    measurement_period: timedelta
    confidence_interval: Tuple[float, float]
    sample_size: int
    created_at: datetime
    last_updated: datetime
    
    def is_within_baseline(self, value: float, tolerance: float = 0.1) -> bool:
        """Check if value is within baseline range."""
        lower_bound = self.baseline_value * (1 - tolerance)
        upper_bound = self.baseline_value * (1 + tolerance)
        return lower_bound <= value <= upper_bound


@dataclass
class RegressionResult:
    """Performance regression detection result."""
    metric_name: str
    detected_at: datetime
    regression_type: str  # "performance", "reliability", "efficiency"
    severity: str  # "minor", "major", "critical"
    current_value: float
    baseline_value: float
    degradation_percentage: float
    statistical_significance: float
    affected_period: Tuple[datetime, datetime]
    root_cause_hints: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'metric_name': self.metric_name,
            'detected_at': self.detected_at.isoformat(),
            'regression_type': self.regression_type,
            'severity': self.severity,
            'current_value': self.current_value,
            'baseline_value': self.baseline_value,
            'degradation_percentage': self.degradation_percentage,
            'statistical_significance': self.statistical_significance,
            'affected_period': [
                self.affected_period[0].isoformat(),
                self.affected_period[1].isoformat()
            ],
            'root_cause_hints': self.root_cause_hints
        }


@dataclass
class SLACompliance:
    """SLA compliance analysis."""
    sla_name: str
    target_value: float
    actual_value: float
    compliance_percentage: float
    measurement_period: Tuple[datetime, datetime]
    violations_count: int
    max_violation_duration: Optional[timedelta] = None
    average_violation_severity: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'sla_name': self.sla_name,
            'target_value': self.target_value,
            'actual_value': self.actual_value,
            'compliance_percentage': self.compliance_percentage,
            'measurement_period': [
                self.measurement_period[0].isoformat(),
                self.measurement_period[1].isoformat()
            ],
            'violations_count': self.violations_count,
            'max_violation_duration': self.max_violation_duration.total_seconds() if self.max_violation_duration else None,
            'average_violation_severity': self.average_violation_severity
        }


class TimeSeriesAnalyzer:
    """Time series analysis for performance metrics."""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
    
    def analyze_trend(self, data: List[Tuple[datetime, float]], metric_name: str) -> TrendAnalysis:
        """Analyze trend in time series data."""
        if len(data) < 10:
            return TrendAnalysis(
                metric_name=metric_name,
                time_period="insufficient_data",
                direction=TrendDirection.UNKNOWN,
                slope=0.0,
                correlation_coefficient=0.0,
                p_value=1.0,
                confidence=0.0,
                start_value=0.0,
                end_value=0.0,
                change_percentage=0.0,
                volatility=0.0
            )
        
        try:
            # Convert to numpy arrays
            timestamps = np.array([t.timestamp() for t, v in data])
            values = np.array([v for t, v in data])
            
            # Normalize timestamps
            timestamps = (timestamps - timestamps.min()) / (timestamps.max() - timestamps.min())
            
            # Linear regression
            if SKLEARN_AVAILABLE:
                X = timestamps.reshape(-1, 1)
                model = LinearRegression()
                model.fit(X, values)
                
                slope = model.coef_[0]
                r_value = np.corrcoef(timestamps, values)[0, 1]
                
                # Calculate p-value (simplified)
                n = len(values)
                t_stat = r_value * np.sqrt((n - 2) / (1 - r_value**2))
                from scipy import stats
                p_value = 2 * (1 - stats.t.cdf(abs(t_stat), n - 2)) if 'stats' in globals() else 0.05
                
            else:
                # Simple linear regression without sklearn
                slope = np.polyfit(timestamps, values, 1)[0]
                r_value = np.corrcoef(timestamps, values)[0, 1]
                p_value = 0.05  # Simplified
            
            # Determine trend direction
            if abs(slope) < 0.1:
                direction = TrendDirection.STABLE
            elif slope > 0:
                direction = TrendDirection.INCREASING
            else:
                direction = TrendDirection.DECREASING
            
            # Calculate volatility (coefficient of variation)
            volatility = np.std(values) / np.mean(values) if np.mean(values) != 0 else 0
            
            if volatility > 0.3:  # High volatility
                direction = TrendDirection.VOLATILE
            
            # Calculate change percentage
            start_value = values[0]
            end_value = values[-1]
            change_percentage = ((end_value - start_value) / start_value * 100) if start_value != 0 else 0
            
            # Confidence based on R² and p-value
            confidence = (r_value**2) * (1 - p_value) if p_value < 0.05 else 0.0
            
            time_period = f"{data[0][0].isoformat()}_to_{data[-1][0].isoformat()}"
            
            return TrendAnalysis(
                metric_name=metric_name,
                time_period=time_period,
                direction=direction,
                slope=slope,
                correlation_coefficient=r_value,
                p_value=p_value,
                confidence=confidence,
                start_value=start_value,
                end_value=end_value,
                change_percentage=change_percentage,
                volatility=volatility
            )
            
        except Exception as e:
            logger.error(f"Error analyzing trend for {metric_name}: {e}")
            return TrendAnalysis(
                metric_name=metric_name,
                time_period="error",
                direction=TrendDirection.UNKNOWN,
                slope=0.0,
                correlation_coefficient=0.0,
                p_value=1.0,
                confidence=0.0,
                start_value=0.0,
                end_value=0.0,
                change_percentage=0.0,
                volatility=0.0,
                metadata={'error': str(e)}
            )
    
    def forecast_capacity(self, data: List[Tuple[datetime, float]], metric_name: str,
                         forecast_days: int = 30, threshold: Optional[float] = None) -> CapacityForecast:
        """Forecast capacity based on historical data."""
        if len(data) < 30:  # Need sufficient data for forecasting
            return CapacityForecast(
                metric_name=metric_name,
                resource_type="unknown",
                current_value=data[-1][1] if data else 0.0,
                predicted_value=data[-1][1] if data else 0.0,
                forecast_date=datetime.now(timezone.utc) + timedelta(days=forecast_days),
                confidence_level=ForecastConfidence.UNRELIABLE,
                confidence_interval=(0.0, 0.0),
                time_to_threshold=None,
                threshold_value=threshold,
                model_accuracy=0.0
            )
        
        try:
            # Prepare data
            timestamps = np.array([t.timestamp() for t, v in data])
            values = np.array([v for t, v in data])
            
            # Normalize timestamps
            start_time = timestamps.min()
            timestamps_norm = (timestamps - start_time) / 3600  # Hours from start
            
            current_value = values[-1]
            forecast_timestamp = start_time + (len(data) + forecast_days * 24) * 3600  # Forecast point
            forecast_timestamp_norm = (forecast_timestamp - start_time) / 3600
            
            if SKLEARN_AVAILABLE:
                # Use multiple models and ensemble
                models = {
                    'linear': LinearRegression(),
                    'ridge': Ridge(alpha=1.0),
                    'polynomial': LinearRegression()
                }
                
                predictions = {}
                accuracies = {}
                
                # Split data for validation
                X = timestamps_norm.reshape(-1, 1)
                X_train, X_test, y_train, y_test = train_test_split(X, values, test_size=0.2, random_state=42)
                
                for model_name, model in models.items():
                    try:
                        if model_name == 'polynomial':
                            # Polynomial features for non-linear trends
                            poly_features = PolynomialFeatures(degree=2)
                            X_train_poly = poly_features.fit_transform(X_train)
                            X_test_poly = poly_features.transform(X_test)
                            
                            model.fit(X_train_poly, y_train)
                            y_pred_test = model.predict(X_test_poly)
                            
                            # Forecast
                            X_forecast = poly_features.transform([[forecast_timestamp_norm]])
                            prediction = model.predict(X_forecast)[0]
                        else:
                            model.fit(X_train, y_train)
                            y_pred_test = model.predict(X_test)
                            
                            # Forecast
                            prediction = model.predict([[forecast_timestamp_norm]])[0]
                        
                        # Calculate accuracy
                        accuracy = max(0, 1 - mean_squared_error(y_test, y_pred_test) / np.var(y_test))
                        
                        predictions[model_name] = prediction
                        accuracies[model_name] = accuracy
                        
                    except Exception as e:
                        logger.debug(f"Error with {model_name} model: {e}")
                        continue
                
                if predictions:
                    # Ensemble prediction (weighted by accuracy)
                    total_weight = sum(accuracies.values())
                    if total_weight > 0:
                        predicted_value = sum(pred * accuracies[name] for name, pred in predictions.items()) / total_weight
                        model_accuracy = sum(accuracies.values()) / len(accuracies)
                    else:
                        predicted_value = statistics.mean(predictions.values())
                        model_accuracy = 0.0
                else:
                    # Fallback to simple trend
                    trend = np.polyfit(timestamps_norm, values, 1)
                    predicted_value = trend[0] * forecast_timestamp_norm + trend[1]
                    model_accuracy = 0.3  # Low accuracy fallback
                
            else:
                # Simple linear trend without sklearn
                trend = np.polyfit(timestamps_norm, values, 1)
                predicted_value = trend[0] * forecast_timestamp_norm + trend[1]
                model_accuracy = 0.3  # Low accuracy without proper validation
            
            # Calculate confidence interval (simplified)
            data_std = np.std(values)
            confidence_margin = 1.96 * data_std  # 95% confidence interval
            confidence_interval = (predicted_value - confidence_margin, predicted_value + confidence_margin)
            
            # Determine confidence level
            if model_accuracy > 0.9:
                confidence_level = ForecastConfidence.HIGH
            elif model_accuracy > 0.7:
                confidence_level = ForecastConfidence.MEDIUM
            elif model_accuracy > 0.5:
                confidence_level = ForecastConfidence.LOW
            else:
                confidence_level = ForecastConfidence.UNRELIABLE
            
            # Calculate time to threshold
            time_to_threshold = None
            if threshold and predicted_value != current_value:
                # Simple linear projection to threshold
                rate_per_hour = (predicted_value - current_value) / (forecast_days * 24)
                if rate_per_hour > 0 and current_value < threshold:
                    hours_to_threshold = (threshold - current_value) / rate_per_hour
                    time_to_threshold = timedelta(hours=hours_to_threshold)
            
            forecast_date = datetime.fromtimestamp(forecast_timestamp, timezone.utc)
            
            return CapacityForecast(
                metric_name=metric_name,
                resource_type=self._determine_resource_type(metric_name),
                current_value=current_value,
                predicted_value=predicted_value,
                forecast_date=forecast_date,
                confidence_level=confidence_level,
                confidence_interval=confidence_interval,
                time_to_threshold=time_to_threshold,
                threshold_value=threshold,
                model_accuracy=model_accuracy
            )
            
        except Exception as e:
            logger.error(f"Error forecasting capacity for {metric_name}: {e}")
            return CapacityForecast(
                metric_name=metric_name,
                resource_type="unknown",
                current_value=data[-1][1] if data else 0.0,
                predicted_value=data[-1][1] if data else 0.0,
                forecast_date=datetime.now(timezone.utc) + timedelta(days=forecast_days),
                confidence_level=ForecastConfidence.UNRELIABLE,
                confidence_interval=(0.0, 0.0),
                time_to_threshold=None,
                threshold_value=threshold,
                model_accuracy=0.0
            )
    
    def _determine_resource_type(self, metric_name: str) -> str:
        """Determine resource type from metric name."""
        if 'cpu' in metric_name.lower():
            return 'cpu'
        elif 'memory' in metric_name.lower():
            return 'memory'
        elif 'disk' in metric_name.lower():
            return 'disk'
        elif 'network' in metric_name.lower():
            return 'network'
        elif 'request' in metric_name.lower() or 'response' in metric_name.lower():
            return 'api'
        elif 'database' in metric_name.lower() or 'query' in metric_name.lower():
            return 'database'
        else:
            return 'unknown'
    
    def detect_seasonal_patterns(self, data: List[Tuple[datetime, float]]) -> Dict[str, Any]:
        """Detect seasonal patterns in the data."""
        if len(data) < 168:  # Need at least a week of hourly data
            return {'has_pattern': False, 'confidence': 0.0}
        
        try:
            timestamps = [t for t, v in data]
            values = [v for t, v in data]
            
            # Extract time features
            hours = [t.hour for t in timestamps]
            days = [t.weekday() for t in timestamps]
            
            # Group by hour and day to find patterns
            hourly_means = defaultdict(list)
            daily_means = defaultdict(list)
            
            for i, (hour, day, value) in enumerate(zip(hours, days, values)):
                hourly_means[hour].append(value)
                daily_means[day].append(value)
            
            # Calculate average values for each hour/day
            hourly_avg = {hour: statistics.mean(vals) for hour, vals in hourly_means.items()}
            daily_avg = {day: statistics.mean(vals) for day, vals in daily_means.items()}
            
            # Calculate coefficient of variation to detect patterns
            hourly_cv = statistics.stdev(hourly_avg.values()) / statistics.mean(hourly_avg.values())
            daily_cv = statistics.stdev(daily_avg.values()) / statistics.mean(daily_avg.values())
            
            # Determine if there's a significant pattern
            has_hourly_pattern = hourly_cv > 0.1  # 10% variation
            has_daily_pattern = daily_cv > 0.05   # 5% variation
            
            pattern_strength = max(hourly_cv, daily_cv)
            confidence = min(1.0, pattern_strength * 2)  # Scale to confidence
            
            return {
                'has_pattern': has_hourly_pattern or has_daily_pattern,
                'hourly_pattern': has_hourly_pattern,
                'daily_pattern': has_daily_pattern,
                'pattern_strength': pattern_strength,
                'confidence': confidence,
                'hourly_averages': hourly_avg,
                'daily_averages': daily_avg
            }
            
        except Exception as e:
            logger.error(f"Error detecting seasonal patterns: {e}")
            return {'has_pattern': False, 'confidence': 0.0, 'error': str(e)}


class RegressionDetector:
    """Performance regression detection."""
    
    def __init__(self):
        self.baselines: Dict[str, PerformanceBaseline] = {}
        self.detection_sensitivity = 0.05  # 5% change threshold
        self.min_samples_for_detection = 20
    
    def create_baseline(self, metric_name: str, data: List[Tuple[datetime, float]], 
                       measurement_period: timedelta = timedelta(days=7)) -> PerformanceBaseline:
        """Create performance baseline from historical data."""
        if len(data) < 10:
            raise ValueError("Insufficient data to create baseline")
        
        values = [v for t, v in data]
        
        baseline_value = statistics.mean(values)
        std_dev = statistics.stdev(values) if len(values) > 1 else 0
        
        # Acceptable range (mean ± 2 standard deviations)
        acceptable_range = (baseline_value - 2 * std_dev, baseline_value + 2 * std_dev)
        
        # Confidence interval (mean ± 1.96 * std_error)
        std_error = std_dev / np.sqrt(len(values))
        confidence_interval = (
            baseline_value - 1.96 * std_error,
            baseline_value + 1.96 * std_error
        )
        
        baseline = PerformanceBaseline(
            metric_name=metric_name,
            baseline_value=baseline_value,
            acceptable_range=acceptable_range,
            measurement_period=measurement_period,
            confidence_interval=confidence_interval,
            sample_size=len(values),
            created_at=datetime.now(timezone.utc),
            last_updated=datetime.now(timezone.utc)
        )
        
        self.baselines[metric_name] = baseline
        return baseline
    
    def detect_regression(self, metric_name: str, recent_data: List[Tuple[datetime, float]]) -> Optional[RegressionResult]:
        """Detect performance regression."""
        if metric_name not in self.baselines:
            return None
        
        if len(recent_data) < self.min_samples_for_detection:
            return None
        
        baseline = self.baselines[metric_name]
        recent_values = [v for t, v in recent_data]
        recent_mean = statistics.mean(recent_values)
        
        # Calculate degradation percentage
        degradation_percentage = ((recent_mean - baseline.baseline_value) / baseline.baseline_value) * 100
        
        # Determine if this is a significant regression
        is_regression = False
        severity = "minor"
        
        # For response time metrics, higher is worse
        if 'time' in metric_name.lower() or 'duration' in metric_name.lower() or 'latency' in metric_name.lower():
            if degradation_percentage > 50:
                is_regression = True
                severity = "critical"
            elif degradation_percentage > 20:
                is_regression = True
                severity = "major"
            elif degradation_percentage > 10:
                is_regression = True
                severity = "minor"
        
        # For throughput metrics, lower is worse
        elif 'throughput' in metric_name.lower() or 'rate' in metric_name.lower():
            if degradation_percentage < -30:
                is_regression = True
                severity = "critical"
            elif degradation_percentage < -15:
                is_regression = True
                severity = "major"
            elif degradation_percentage < -5:
                is_regression = True
                severity = "minor"
        
        # For error rates, higher is worse
        elif 'error' in metric_name.lower():
            if degradation_percentage > 100:
                is_regression = True
                severity = "critical"
            elif degradation_percentage > 50:
                is_regression = True
                severity = "major"
            elif degradation_percentage > 25:
                is_regression = True
                severity = "minor"
        
        if not is_regression:
            return None
        
        # Statistical significance test (simplified)
        baseline_std = (baseline.acceptable_range[1] - baseline.acceptable_range[0]) / 4
        recent_std = statistics.stdev(recent_values) if len(recent_values) > 1 else baseline_std
        
        # Combined standard error
        combined_se = np.sqrt((baseline_std**2 / baseline.sample_size) + (recent_std**2 / len(recent_values)))
        
        # Z-score
        z_score = abs(recent_mean - baseline.baseline_value) / combined_se if combined_se > 0 else 0
        statistical_significance = min(1.0, z_score / 3.0)  # Normalize to [0, 1]
        
        # Generate root cause hints
        root_cause_hints = self._generate_root_cause_hints(metric_name, degradation_percentage, severity)
        
        return RegressionResult(
            metric_name=metric_name,
            detected_at=datetime.now(timezone.utc),
            regression_type=self._determine_regression_type(metric_name),
            severity=severity,
            current_value=recent_mean,
            baseline_value=baseline.baseline_value,
            degradation_percentage=degradation_percentage,
            statistical_significance=statistical_significance,
            affected_period=(recent_data[0][0], recent_data[-1][0]),
            root_cause_hints=root_cause_hints
        )
    
    def _determine_regression_type(self, metric_name: str) -> str:
        """Determine type of regression."""
        if any(keyword in metric_name.lower() for keyword in ['time', 'duration', 'latency', 'response']):
            return 'performance'
        elif any(keyword in metric_name.lower() for keyword in ['error', 'fail', 'exception']):
            return 'reliability'
        elif any(keyword in metric_name.lower() for keyword in ['cpu', 'memory', 'resource', 'utilization']):
            return 'efficiency'
        else:
            return 'performance'
    
    def _generate_root_cause_hints(self, metric_name: str, degradation_percentage: float, severity: str) -> List[str]:
        """Generate root cause analysis hints."""
        hints = []
        
        if 'response' in metric_name.lower() or 'latency' in metric_name.lower():
            hints.extend([
                "Check for increased database query times",
                "Verify network connectivity and bandwidth",
                "Review recent application deployments",
                "Check for memory leaks or garbage collection issues"
            ])
        
        if 'memory' in metric_name.lower():
            hints.extend([
                "Look for memory leaks in recent code changes",
                "Check for increased data processing workloads",
                "Review caching efficiency and memory pools"
            ])
        
        if 'cpu' in metric_name.lower():
            hints.extend([
                "Check for inefficient algorithms or loops",
                "Review concurrent processing and thread usage",
                "Look for blocking operations or synchronization issues"
            ])
        
        if 'error' in metric_name.lower():
            hints.extend([
                "Review recent application logs for error patterns",
                "Check external service dependencies",
                "Verify input validation and data quality"
            ])
        
        if severity == "critical" and degradation_percentage > 50:
            hints.append("Consider immediate rollback of recent changes")
        
        return hints


class SLAAnalyzer:
    """SLA compliance analysis."""
    
    def __init__(self):
        self.sla_definitions = {}
    
    def define_sla(self, sla_name: str, metric_name: str, target_value: float, 
                   comparison: str = "less_than"):  # "less_than", "greater_than", "equals"
        """Define an SLA."""
        self.sla_definitions[sla_name] = {
            'metric_name': metric_name,
            'target_value': target_value,
            'comparison': comparison
        }
    
    def analyze_sla_compliance(self, sla_name: str, data: List[Tuple[datetime, float]], 
                              measurement_period: Optional[Tuple[datetime, datetime]] = None) -> SLACompliance:
        """Analyze SLA compliance."""
        if sla_name not in self.sla_definitions:
            raise ValueError(f"SLA '{sla_name}' not defined")
        
        sla_def = self.sla_definitions[sla_name]
        target_value = sla_def['target_value']
        comparison = sla_def['comparison']
        
        if not data:
            return SLACompliance(
                sla_name=sla_name,
                target_value=target_value,
                actual_value=0.0,
                compliance_percentage=0.0,
                measurement_period=measurement_period or (datetime.now(timezone.utc), datetime.now(timezone.utc)),
                violations_count=0
            )
        
        values = [v for t, v in data]
        actual_value = statistics.mean(values)
        
        # Calculate compliance
        compliant_values = []
        violations = []
        
        for timestamp, value in data:
            if comparison == "less_than":
                is_compliant = value <= target_value
            elif comparison == "greater_than":
                is_compliant = value >= target_value
            else:  # equals (with tolerance)
                tolerance = target_value * 0.05  # 5% tolerance
                is_compliant = abs(value - target_value) <= tolerance
            
            if is_compliant:
                compliant_values.append(value)
            else:
                violations.append((timestamp, value))
        
        compliance_percentage = (len(compliant_values) / len(values)) * 100
        
        # Analyze violations
        max_violation_duration = None
        average_violation_severity = None
        
        if violations:
            violation_severities = []
            violation_durations = []
            
            # Group consecutive violations
            current_violation_start = None
            
            for i, (timestamp, value) in enumerate(data):
                is_violation = any(vt == timestamp for vt, vv in violations)
                
                if is_violation:
                    if current_violation_start is None:
                        current_violation_start = timestamp
                    
                    # Calculate severity (percentage deviation from target)
                    if comparison == "less_than":
                        severity = ((value - target_value) / target_value) * 100
                    elif comparison == "greater_than":
                        severity = ((target_value - value) / target_value) * 100
                    else:
                        severity = (abs(value - target_value) / target_value) * 100
                    
                    violation_severities.append(max(0, severity))
                
                else:
                    if current_violation_start is not None:
                        duration = timestamp - current_violation_start
                        violation_durations.append(duration)
                        current_violation_start = None
            
            # Handle violation that continues to the end
            if current_violation_start is not None:
                duration = data[-1][0] - current_violation_start
                violation_durations.append(duration)
            
            if violation_severities:
                average_violation_severity = statistics.mean(violation_severities)
            
            if violation_durations:
                max_violation_duration = max(violation_durations)
        
        period = measurement_period or (data[0][0], data[-1][0])
        
        return SLACompliance(
            sla_name=sla_name,
            target_value=target_value,
            actual_value=actual_value,
            compliance_percentage=compliance_percentage,
            measurement_period=period,
            violations_count=len(violations),
            max_violation_duration=max_violation_duration,
            average_violation_severity=average_violation_severity
        )


class PerformanceAnalyticsEngine:
    """
    Main performance analytics engine that coordinates trend analysis,
    capacity forecasting, regression detection, and SLA compliance monitoring.
    """
    
    def __init__(self, db_path: str = "performance_metrics.db"):
        self.db_path = db_path
        self.time_series_analyzer = TimeSeriesAnalyzer()
        self.regression_detector = RegressionDetector()
        self.sla_analyzer = SLAAnalyzer()
        
        # Configuration
        self.enabled = True
        self.analysis_interval = 3600  # 1 hour
        self.retention_days = 90
        
        # Analytics state
        self.running = False
        self.analytics_task: Optional[asyncio.Task] = None
        
        # Results cache
        self.trend_cache = {}
        self.forecast_cache = {}
        self.regression_cache = {}
        
        # Initialize default SLAs
        self._setup_default_slas()
    
    async def initialize(self):
        """Initialize the analytics engine."""
        await self._create_analytics_tables()
        
        logger.info("Performance Analytics Engine initialized")
    
    async def _create_analytics_tables(self):
        """Create analytics database tables."""
        async with aiosqlite.connect(self.db_path) as db:
            # Trend analysis results
            await db.execute("""
                CREATE TABLE IF NOT EXISTS trend_analysis (
                    id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    time_period TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    slope REAL,
                    correlation_coefficient REAL,
                    p_value REAL,
                    confidence REAL,
                    start_value REAL,
                    end_value REAL,
                    change_percentage REAL,
                    volatility REAL,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Capacity forecasts
            await db.execute("""
                CREATE TABLE IF NOT EXISTS capacity_forecasts (
                    id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    current_value REAL NOT NULL,
                    predicted_value REAL NOT NULL,
                    forecast_date TEXT NOT NULL,
                    confidence_level TEXT NOT NULL,
                    confidence_interval_lower REAL,
                    confidence_interval_upper REAL,
                    time_to_threshold_seconds REAL,
                    threshold_value REAL,
                    model_accuracy REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Performance baselines
            await db.execute("""
                CREATE TABLE IF NOT EXISTS performance_baselines (
                    metric_name TEXT PRIMARY KEY,
                    baseline_value REAL NOT NULL,
                    acceptable_range_lower REAL,
                    acceptable_range_upper REAL,
                    measurement_period_seconds INTEGER,
                    confidence_interval_lower REAL,
                    confidence_interval_upper REAL,
                    sample_size INTEGER,
                    created_at TEXT NOT NULL,
                    last_updated TEXT NOT NULL
                )
            """)
            
            # Regression detection results
            await db.execute("""
                CREATE TABLE IF NOT EXISTS regression_detections (
                    id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    detected_at TEXT NOT NULL,
                    regression_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    current_value REAL NOT NULL,
                    baseline_value REAL NOT NULL,
                    degradation_percentage REAL,
                    statistical_significance REAL,
                    affected_period_start TEXT,
                    affected_period_end TEXT,
                    root_cause_hints TEXT,
                    is_resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # SLA compliance results
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sla_compliance (
                    id TEXT PRIMARY KEY,
                    sla_name TEXT NOT NULL,
                    target_value REAL NOT NULL,
                    actual_value REAL NOT NULL,
                    compliance_percentage REAL NOT NULL,
                    measurement_period_start TEXT NOT NULL,
                    measurement_period_end TEXT NOT NULL,
                    violations_count INTEGER,
                    max_violation_duration_seconds REAL,
                    average_violation_severity REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_trend_analysis_metric ON trend_analysis(metric_name, created_at)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_capacity_forecasts_metric ON capacity_forecasts(metric_name, forecast_date)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_regression_detections_metric ON regression_detections(metric_name, detected_at)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sla_compliance_name ON sla_compliance(sla_name, created_at)")
            
            await db.commit()
    
    def _setup_default_slas(self):
        """Setup default SLA definitions."""
        # API response time SLA
        self.sla_analyzer.define_sla("api_response_time_p95", "request_duration_p95_ms", 500.0, "less_than")
        
        # Error rate SLA
        self.sla_analyzer.define_sla("api_error_rate", "error_rate_percent", 1.0, "less_than")
        
        # System availability SLA
        self.sla_analyzer.define_sla("system_availability", "uptime_percentage", 99.9, "greater_than")
        
        # Database query performance SLA
        self.sla_analyzer.define_sla("db_query_performance", "db_query_duration_avg_ms", 100.0, "less_than")
    
    async def start_analytics(self):
        """Start analytics processing."""
        if self.running:
            return
        
        self.running = True
        self.analytics_task = asyncio.create_task(self._analytics_loop())
        
        logger.info("Performance analytics started")
    
    async def stop_analytics(self):
        """Stop analytics processing."""
        if not self.running:
            return
        
        self.running = False
        
        if self.analytics_task:
            self.analytics_task.cancel()
            try:
                await self.analytics_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Performance analytics stopped")
    
    async def _analytics_loop(self):
        """Main analytics processing loop."""
        while self.running:
            try:
                # Get list of metrics to analyze
                metrics_to_analyze = await self._get_metrics_for_analysis()
                
                # Perform analytics for each metric
                for metric_name in metrics_to_analyze:
                    await self._analyze_metric(metric_name)
                
                await asyncio.sleep(self.analysis_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in analytics loop: {e}")
                await asyncio.sleep(self.analysis_interval)
    
    async def _get_metrics_for_analysis(self) -> List[str]:
        """Get list of metrics that have enough data for analysis."""
        try:
            # Look for metrics with sufficient recent data
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT name, COUNT(*) as data_points
                    FROM (
                        SELECT metric_name as name FROM infrastructure_metrics 
                        WHERE timestamp >= ?
                        UNION ALL
                        SELECT metric_name as name FROM performance_issues 
                        WHERE detected_at >= ?
                    ) 
                    GROUP BY name
                    HAVING data_points >= 50
                    ORDER BY data_points DESC
                    LIMIT 20
                """, (cutoff_time.isoformat(), cutoff_time.isoformat()))
                
                metrics = [row[0] for row in await cursor.fetchall()]
                return metrics
                
        except Exception as e:
            logger.error(f"Error getting metrics for analysis: {e}")
            return []
    
    async def _analyze_metric(self, metric_name: str):
        """Perform comprehensive analysis for a metric."""
        try:
            # Get historical data
            data = await self._get_metric_data(metric_name, days=30)
            
            if len(data) < 20:
                return
            
            # Trend analysis
            trend_result = self.time_series_analyzer.analyze_trend(data, metric_name)
            await self._store_trend_analysis(trend_result)
            self.trend_cache[metric_name] = trend_result
            
            # Capacity forecasting
            threshold = self._get_threshold_for_metric(metric_name)
            forecast_result = self.time_series_analyzer.forecast_capacity(data, metric_name, threshold=threshold)
            await self._store_capacity_forecast(forecast_result)
            self.forecast_cache[metric_name] = forecast_result
            
            # Regression detection (if we have a baseline)
            recent_data = data[-50:]  # Last 50 data points
            if metric_name not in self.regression_detector.baselines:
                # Create baseline from older data
                baseline_data = data[:-50] if len(data) > 100 else data[:len(data)//2]
                if len(baseline_data) >= 20:
                    try:
                        self.regression_detector.create_baseline(metric_name, baseline_data)
                        await self._store_performance_baseline(self.regression_detector.baselines[metric_name])
                    except ValueError:
                        pass  # Not enough data for baseline
            
            if metric_name in self.regression_detector.baselines:
                regression_result = self.regression_detector.detect_regression(metric_name, recent_data)
                if regression_result:
                    await self._store_regression_detection(regression_result)
                    self.regression_cache[metric_name] = regression_result
            
            # SLA compliance (for relevant metrics)
            for sla_name, sla_def in self.sla_analyzer.sla_definitions.items():
                if sla_def['metric_name'] == metric_name:
                    compliance_result = self.sla_analyzer.analyze_sla_compliance(sla_name, data)
                    await self._store_sla_compliance(compliance_result)
            
        except Exception as e:
            logger.error(f"Error analyzing metric {metric_name}: {e}")
    
    async def _get_metric_data(self, metric_name: str, days: int = 30) -> List[Tuple[datetime, float]]:
        """Get historical data for a metric."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=days)
            
            async with aiosqlite.connect(self.db_path) as db:
                # Try to get from infrastructure metrics first
                cursor = await db.execute("""
                    SELECT timestamp, metrics
                    FROM infrastructure_metrics
                    WHERE resource_id LIKE ? AND timestamp >= ?
                    ORDER BY timestamp
                """, (f"%{metric_name}%", cutoff_time.isoformat()))
                
                rows = await cursor.fetchall()
                data = []
                
                for timestamp_str, metrics_json in rows:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str)
                        metrics = json.loads(metrics_json)
                        
                        # Extract the specific metric value
                        value = self._extract_metric_value(metrics, metric_name)
                        if value is not None:
                            data.append((timestamp, value))
                    except Exception:
                        continue
                
                # If no data found, try performance metrics table
                if not data:
                    cursor = await db.execute("""
                        SELECT timestamp, value
                        FROM metric_points
                        WHERE name = ? AND timestamp >= ?
                        ORDER BY timestamp
                    """, (metric_name, cutoff_time.isoformat()))
                    
                    rows = await cursor.fetchall()
                    for timestamp_str, value in rows:
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str)
                            data.append((timestamp, float(value)))
                        except Exception:
                            continue
                
                return data
                
        except Exception as e:
            logger.error(f"Error getting metric data for {metric_name}: {e}")
            return []
    
    def _extract_metric_value(self, metrics: Dict[str, Any], metric_name: str) -> Optional[float]:
        """Extract specific metric value from metrics dictionary."""
        # Try exact match first
        if metric_name in metrics:
            return float(metrics[metric_name])
        
        # Try partial matches
        for key, value in metrics.items():
            if metric_name.lower() in key.lower():
                try:
                    return float(value)
                except (ValueError, TypeError):
                    continue
        
        return None
    
    def _get_threshold_for_metric(self, metric_name: str) -> Optional[float]:
        """Get threshold value for capacity forecasting."""
        # Define thresholds for common metrics
        thresholds = {
            'cpu_usage_percent': 90.0,
            'memory_usage_percent': 95.0,
            'disk_usage_percent': 95.0,
            'request_duration_avg_ms': 1000.0,
            'error_rate_percent': 5.0
        }
        
        for threshold_key, threshold_value in thresholds.items():
            if threshold_key in metric_name.lower():
                return threshold_value
        
        return None
    
    async def _store_trend_analysis(self, trend: TrendAnalysis):
        """Store trend analysis results."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO trend_analysis 
                    (id, metric_name, time_period, direction, slope, correlation_coefficient,
                     p_value, confidence, start_value, end_value, change_percentage, volatility, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    trend.metric_name,
                    trend.time_period,
                    trend.direction.value,
                    trend.slope,
                    trend.correlation_coefficient,
                    trend.p_value,
                    trend.confidence,
                    trend.start_value,
                    trend.end_value,
                    trend.change_percentage,
                    trend.volatility,
                    json.dumps(trend.metadata)
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error storing trend analysis: {e}")
    
    async def _store_capacity_forecast(self, forecast: CapacityForecast):
        """Store capacity forecast results."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO capacity_forecasts 
                    (id, metric_name, resource_type, current_value, predicted_value, forecast_date,
                     confidence_level, confidence_interval_lower, confidence_interval_upper,
                     time_to_threshold_seconds, threshold_value, model_accuracy)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    forecast.metric_name,
                    forecast.resource_type,
                    forecast.current_value,
                    forecast.predicted_value,
                    forecast.forecast_date.isoformat(),
                    forecast.confidence_level.value,
                    forecast.confidence_interval[0],
                    forecast.confidence_interval[1],
                    forecast.time_to_threshold.total_seconds() if forecast.time_to_threshold else None,
                    forecast.threshold_value,
                    forecast.model_accuracy
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error storing capacity forecast: {e}")
    
    async def _store_performance_baseline(self, baseline: PerformanceBaseline):
        """Store performance baseline."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO performance_baselines 
                    (metric_name, baseline_value, acceptable_range_lower, acceptable_range_upper,
                     measurement_period_seconds, confidence_interval_lower, confidence_interval_upper,
                     sample_size, created_at, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    baseline.metric_name,
                    baseline.baseline_value,
                    baseline.acceptable_range[0],
                    baseline.acceptable_range[1],
                    baseline.measurement_period.total_seconds(),
                    baseline.confidence_interval[0],
                    baseline.confidence_interval[1],
                    baseline.sample_size,
                    baseline.created_at.isoformat(),
                    baseline.last_updated.isoformat()
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error storing performance baseline: {e}")
    
    async def _store_regression_detection(self, regression: RegressionResult):
        """Store regression detection results."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO regression_detections 
                    (id, metric_name, detected_at, regression_type, severity, current_value,
                     baseline_value, degradation_percentage, statistical_significance,
                     affected_period_start, affected_period_end, root_cause_hints)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    regression.metric_name,
                    regression.detected_at.isoformat(),
                    regression.regression_type,
                    regression.severity,
                    regression.current_value,
                    regression.baseline_value,
                    regression.degradation_percentage,
                    regression.statistical_significance,
                    regression.affected_period[0].isoformat(),
                    regression.affected_period[1].isoformat(),
                    json.dumps(regression.root_cause_hints)
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error storing regression detection: {e}")
    
    async def _store_sla_compliance(self, compliance: SLACompliance):
        """Store SLA compliance results."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT INTO sla_compliance 
                    (id, sla_name, target_value, actual_value, compliance_percentage,
                     measurement_period_start, measurement_period_end, violations_count,
                     max_violation_duration_seconds, average_violation_severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    str(uuid.uuid4()),
                    compliance.sla_name,
                    compliance.target_value,
                    compliance.actual_value,
                    compliance.compliance_percentage,
                    compliance.measurement_period[0].isoformat(),
                    compliance.measurement_period[1].isoformat(),
                    compliance.violations_count,
                    compliance.max_violation_duration.total_seconds() if compliance.max_violation_duration else None,
                    compliance.average_violation_severity
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error storing SLA compliance: {e}")
    
    async def get_analytics_summary(self) -> Dict[str, Any]:
        """Get comprehensive analytics summary."""
        try:
            summary = {
                'trends': {},
                'forecasts': {},
                'regressions': {},
                'sla_compliance': {},
                'overall_health': 'unknown'
            }
            
            # Recent trends
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT metric_name, direction, change_percentage, confidence
                    FROM trend_analysis
                    WHERE created_at >= ?
                    ORDER BY created_at DESC
                    LIMIT 10
                """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),))
                
                trends = await cursor.fetchall()
                for metric_name, direction, change_pct, confidence in trends:
                    summary['trends'][metric_name] = {
                        'direction': direction,
                        'change_percentage': change_pct,
                        'confidence': confidence
                    }
                
                # Recent forecasts with warnings
                cursor = await db.execute("""
                    SELECT metric_name, resource_type, time_to_threshold_seconds, confidence_level
                    FROM capacity_forecasts
                    WHERE created_at >= ? AND time_to_threshold_seconds IS NOT NULL
                    ORDER BY time_to_threshold_seconds
                    LIMIT 10
                """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),))
                
                forecasts = await cursor.fetchall()
                for metric_name, resource_type, time_to_threshold, confidence in forecasts:
                    summary['forecasts'][metric_name] = {
                        'resource_type': resource_type,
                        'time_to_threshold_hours': time_to_threshold / 3600 if time_to_threshold else None,
                        'confidence_level': confidence
                    }
                
                # Recent regressions
                cursor = await db.execute("""
                    SELECT metric_name, severity, degradation_percentage
                    FROM regression_detections
                    WHERE detected_at >= ? AND is_resolved = FALSE
                    ORDER BY degradation_percentage DESC
                    LIMIT 10
                """, ((datetime.now(timezone.utc) - timedelta(days=7)).isoformat(),))
                
                regressions = await cursor.fetchall()
                for metric_name, severity, degradation_pct in regressions:
                    summary['regressions'][metric_name] = {
                        'severity': severity,
                        'degradation_percentage': degradation_pct
                    }
                
                # SLA compliance
                cursor = await db.execute("""
                    SELECT sla_name, compliance_percentage, violations_count
                    FROM sla_compliance
                    WHERE created_at >= ?
                    ORDER BY compliance_percentage
                    LIMIT 10
                """, ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),))
                
                sla_results = await cursor.fetchall()
                for sla_name, compliance_pct, violations in sla_results:
                    summary['sla_compliance'][sla_name] = {
                        'compliance_percentage': compliance_pct,
                        'violations_count': violations
                    }
            
            # Calculate overall health
            summary['overall_health'] = self._calculate_overall_health(summary)
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting analytics summary: {e}")
            return {}
    
    def _calculate_overall_health(self, summary: Dict[str, Any]) -> str:
        """Calculate overall system health from analytics."""
        health_score = 100.0
        
        # Deduct points for regressions
        for regression in summary.get('regressions', {}).values():
            if regression['severity'] == 'critical':
                health_score -= 20
            elif regression['severity'] == 'major':
                health_score -= 10
            elif regression['severity'] == 'minor':
                health_score -= 5
        
        # Deduct points for SLA violations
        for sla in summary.get('sla_compliance', {}).values():
            compliance = sla['compliance_percentage']
            if compliance < 95:
                health_score -= (100 - compliance) * 0.5
        
        # Deduct points for concerning trends
        for trend in summary.get('trends', {}).values():
            if trend['direction'] == 'increasing' and trend['change_percentage'] > 50:
                health_score -= 10
        
        # Deduct points for capacity concerns
        for forecast in summary.get('forecasts', {}).values():
            time_to_threshold = forecast.get('time_to_threshold_hours')
            if time_to_threshold and time_to_threshold < 168:  # Less than a week
                health_score -= 15
        
        # Determine health level
        if health_score >= 90:
            return 'excellent'
        elif health_score >= 75:
            return 'good'
        elif health_score >= 50:
            return 'fair'
        elif health_score >= 25:
            return 'poor'
        else:
            return 'critical'


# Global analytics engine instance
global_analytics_engine: Optional[PerformanceAnalyticsEngine] = None


def get_analytics_engine() -> Optional[PerformanceAnalyticsEngine]:
    """Get the global analytics engine instance."""
    return global_analytics_engine


async def initialize_analytics_engine(db_path: str = "performance_metrics.db") -> PerformanceAnalyticsEngine:
    """Initialize the global analytics engine."""
    global global_analytics_engine
    
    engine = PerformanceAnalyticsEngine(db_path)
    await engine.initialize()
    global_analytics_engine = engine
    
    return engine