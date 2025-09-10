"""
Predictive Alert Engine

ML-powered anomaly detection and predictive alerting system that learns
from historical patterns to identify performance issues before they
impact users and predicts potential system failures.
"""

import asyncio
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import json
import pickle
from pathlib import Path
import aiosqlite
from collections import defaultdict, deque
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import IsolationForest, RandomForestRegressor
    from sklearn.svm import OneClassSVM
    from sklearn.preprocessing import StandardScaler, RobustScaler
    from sklearn.metrics import mean_squared_error, mean_absolute_error
    from sklearn.model_selection import train_test_split
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available, using simplified anomaly detection")

from .metrics_collector import MetricPoint, MetricType, MetricScope

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of anomalies that can be detected."""
    POINT_ANOMALY = "point"          # Single unusual data point
    CONTEXTUAL_ANOMALY = "contextual" # Unusual in specific context
    COLLECTIVE_ANOMALY = "collective"  # Pattern of points that are unusual
    TREND_ANOMALY = "trend"          # Unusual trend or direction change
    SEASONAL_ANOMALY = "seasonal"    # Deviation from seasonal pattern
    THRESHOLD_BREACH = "threshold"   # Simple threshold violation


class AlertSeverity(Enum):
    """Severity levels for alerts."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class AnomalyDetectionResult:
    """Result of anomaly detection analysis."""
    metric_name: str
    timestamp: datetime
    value: float
    anomaly_type: AnomalyType
    severity: AlertSeverity
    confidence: float
    expected_range: Tuple[float, float]
    deviation_score: float
    context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PredictionResult:
    """Result of predictive analysis."""
    metric_name: str
    prediction_time: datetime
    predicted_value: float
    confidence_interval: Tuple[float, float]
    probability_threshold_breach: float
    time_to_threshold: Optional[timedelta]
    model_accuracy: float
    prediction_horizon: timedelta
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAnomalyDetector:
    """Base class for anomaly detectors."""
    
    def __init__(self, name: str, sensitivity: float = 0.1):
        self.name = name
        self.sensitivity = sensitivity
        self.trained = False
        self.model_data = {}
    
    def train(self, data: np.ndarray, timestamps: np.ndarray = None) -> None:
        """Train the anomaly detector."""
        raise NotImplementedError
    
    def detect(self, data: np.ndarray, timestamps: np.ndarray = None) -> np.ndarray:
        """Detect anomalies in the data."""
        raise NotImplementedError
    
    def get_anomaly_score(self, data: np.ndarray) -> np.ndarray:
        """Get anomaly scores for the data."""
        raise NotImplementedError


class StatisticalAnomalyDetector(BaseAnomalyDetector):
    """Statistical anomaly detector using Z-score and IQR methods."""
    
    def __init__(self, name: str = "statistical", sensitivity: float = 0.1, method: str = "zscore"):
        super().__init__(name, sensitivity)
        self.method = method  # 'zscore', 'iqr', 'modified_zscore'
        self.threshold_factor = 3.0 if method == 'zscore' else 1.5
    
    def train(self, data: np.ndarray, timestamps: np.ndarray = None) -> None:
        """Train statistical parameters."""
        if len(data) < 10:
            logger.warning(f"Insufficient data for training {self.name} detector")
            return
        
        self.model_data = {
            'mean': np.mean(data),
            'std': np.std(data),
            'median': np.median(data),
            'q1': np.percentile(data, 25),
            'q3': np.percentile(data, 75),
            'mad': np.median(np.abs(data - np.median(data)))  # Median Absolute Deviation
        }
        self.trained = True
    
    def detect(self, data: np.ndarray, timestamps: np.ndarray = None) -> np.ndarray:
        """Detect anomalies using statistical methods."""
        if not self.trained:
            return np.zeros(len(data), dtype=bool)
        
        if self.method == 'zscore':
            z_scores = np.abs((data - self.model_data['mean']) / max(self.model_data['std'], 1e-6))
            return z_scores > self.threshold_factor
        
        elif self.method == 'iqr':
            iqr = self.model_data['q3'] - self.model_data['q1']
            lower_bound = self.model_data['q1'] - self.threshold_factor * iqr
            upper_bound = self.model_data['q3'] + self.threshold_factor * iqr
            return (data < lower_bound) | (data > upper_bound)
        
        elif self.method == 'modified_zscore':
            modified_z_scores = 0.6745 * (data - self.model_data['median']) / max(self.model_data['mad'], 1e-6)
            return np.abs(modified_z_scores) > self.threshold_factor
        
        return np.zeros(len(data), dtype=bool)
    
    def get_anomaly_score(self, data: np.ndarray) -> np.ndarray:
        """Get anomaly scores."""
        if not self.trained:
            return np.zeros(len(data))
        
        if self.method == 'zscore':
            return np.abs((data - self.model_data['mean']) / max(self.model_data['std'], 1e-6))
        elif self.method == 'iqr':
            iqr = self.model_data['q3'] - self.model_data['q1']
            center = (self.model_data['q1'] + self.model_data['q3']) / 2
            return np.abs(data - center) / max(iqr, 1e-6)
        else:
            return 0.6745 * np.abs(data - self.model_data['median']) / max(self.model_data['mad'], 1e-6)


class MLAnomalyDetector(BaseAnomalyDetector):
    """Machine learning-based anomaly detector."""
    
    def __init__(self, name: str = "isolation_forest", sensitivity: float = 0.1):
        super().__init__(name, sensitivity)
        self.model = None
        self.scaler = None
        
        if not SKLEARN_AVAILABLE:
            logger.error("scikit-learn is required for ML-based anomaly detection")
            return
        
        if name == "isolation_forest":
            self.model = IsolationForest(contamination=sensitivity, random_state=42)
        elif name == "one_class_svm":
            self.model = OneClassSVM(nu=sensitivity)
        else:
            self.model = IsolationForest(contamination=sensitivity, random_state=42)
        
        self.scaler = RobustScaler()
    
    def train(self, data: np.ndarray, timestamps: np.ndarray = None) -> None:
        """Train the ML model."""
        if not SKLEARN_AVAILABLE or self.model is None:
            return
        
        if len(data) < 50:
            logger.warning(f"Insufficient data for training {self.name} detector")
            return
        
        try:
            # Reshape data for sklearn
            if data.ndim == 1:
                data = data.reshape(-1, 1)
            
            # Scale the data
            scaled_data = self.scaler.fit_transform(data)
            
            # Train the model
            self.model.fit(scaled_data)
            self.trained = True
            
        except Exception as e:
            logger.error(f"Error training ML anomaly detector: {e}")
    
    def detect(self, data: np.ndarray, timestamps: np.ndarray = None) -> np.ndarray:
        """Detect anomalies using ML model."""
        if not self.trained or not SKLEARN_AVAILABLE or self.model is None:
            return np.zeros(len(data), dtype=bool)
        
        try:
            if data.ndim == 1:
                data = data.reshape(-1, 1)
            
            scaled_data = self.scaler.transform(data)
            predictions = self.model.predict(scaled_data)
            
            # Convert predictions to boolean anomaly indicators
            return predictions == -1
            
        except Exception as e:
            logger.error(f"Error in ML anomaly detection: {e}")
            return np.zeros(len(data), dtype=bool)
    
    def get_anomaly_score(self, data: np.ndarray) -> np.ndarray:
        """Get anomaly scores from ML model."""
        if not self.trained or not SKLEARN_AVAILABLE or self.model is None:
            return np.zeros(len(data))
        
        try:
            if data.ndim == 1:
                data = data.reshape(-1, 1)
            
            scaled_data = self.scaler.transform(data)
            scores = self.model.decision_function(scaled_data)
            
            # Normalize scores to [0, 1] range
            return (scores.max() - scores) / (scores.max() - scores.min() + 1e-6)
            
        except Exception as e:
            logger.error(f"Error getting anomaly scores: {e}")
            return np.zeros(len(data))


class TrendAnomalyDetector(BaseAnomalyDetector):
    """Detector for trend-based anomalies."""
    
    def __init__(self, name: str = "trend", sensitivity: float = 0.1, window_size: int = 10):
        super().__init__(name, sensitivity)
        self.window_size = window_size
        self.trend_threshold = 2.0  # Standard deviations for trend change detection
    
    def train(self, data: np.ndarray, timestamps: np.ndarray = None) -> None:
        """Train trend parameters."""
        if len(data) < self.window_size * 2:
            return
        
        # Calculate rolling trends
        trends = []
        for i in range(len(data) - self.window_size + 1):
            window = data[i:i + self.window_size]
            x = np.arange(len(window))
            trend = np.polyfit(x, window, 1)[0]  # Linear trend coefficient
            trends.append(trend)
        
        self.model_data = {
            'trend_mean': np.mean(trends),
            'trend_std': np.std(trends),
            'value_mean': np.mean(data),
            'value_std': np.std(data)
        }
        self.trained = True
    
    def detect(self, data: np.ndarray, timestamps: np.ndarray = None) -> np.ndarray:
        """Detect trend anomalies."""
        if not self.trained or len(data) < self.window_size:
            return np.zeros(len(data), dtype=bool)
        
        anomalies = np.zeros(len(data), dtype=bool)
        
        for i in range(len(data) - self.window_size + 1):
            window = data[i:i + self.window_size]
            x = np.arange(len(window))
            trend = np.polyfit(x, window, 1)[0]
            
            # Check for trend anomaly
            trend_z_score = abs(trend - self.model_data['trend_mean']) / max(self.model_data['trend_std'], 1e-6)
            if trend_z_score > self.trend_threshold:
                anomalies[i:i + self.window_size] = True
        
        return anomalies
    
    def get_anomaly_score(self, data: np.ndarray) -> np.ndarray:
        """Get trend anomaly scores."""
        if not self.trained or len(data) < self.window_size:
            return np.zeros(len(data))
        
        scores = np.zeros(len(data))
        
        for i in range(len(data) - self.window_size + 1):
            window = data[i:i + self.window_size]
            x = np.arange(len(window))
            trend = np.polyfit(x, window, 1)[0]
            
            trend_score = abs(trend - self.model_data['trend_mean']) / max(self.model_data['trend_std'], 1e-6)
            scores[i:i + self.window_size] = np.maximum(scores[i:i + self.window_size], trend_score)
        
        return scores


class SeasonalAnomalyDetector(BaseAnomalyDetector):
    """Detector for seasonal anomalies."""
    
    def __init__(self, name: str = "seasonal", sensitivity: float = 0.1, 
                 period: int = 24):  # 24 for daily seasonality in hourly data
        super().__init__(name, sensitivity)
        self.period = period
    
    def train(self, data: np.ndarray, timestamps: np.ndarray = None) -> None:
        """Train seasonal patterns."""
        if len(data) < self.period * 2:
            return
        
        # Calculate seasonal decomposition (simplified)
        seasonal_means = []
        seasonal_stds = []
        
        for i in range(self.period):
            seasonal_values = data[i::self.period]
            seasonal_means.append(np.mean(seasonal_values))
            seasonal_stds.append(np.std(seasonal_values))
        
        self.model_data = {
            'seasonal_means': np.array(seasonal_means),
            'seasonal_stds': np.array(seasonal_stds),
            'overall_mean': np.mean(data),
            'overall_std': np.std(data)
        }
        self.trained = True
    
    def detect(self, data: np.ndarray, timestamps: np.ndarray = None) -> np.ndarray:
        """Detect seasonal anomalies."""
        if not self.trained:
            return np.zeros(len(data), dtype=bool)
        
        anomalies = np.zeros(len(data), dtype=bool)
        
        for i, value in enumerate(data):
            seasonal_idx = i % self.period
            expected_mean = self.model_data['seasonal_means'][seasonal_idx]
            expected_std = max(self.model_data['seasonal_stds'][seasonal_idx], 1e-6)
            
            z_score = abs(value - expected_mean) / expected_std
            anomalies[i] = z_score > 3.0  # 3 standard deviations
        
        return anomalies
    
    def get_anomaly_score(self, data: np.ndarray) -> np.ndarray:
        """Get seasonal anomaly scores."""
        if not self.trained:
            return np.zeros(len(data))
        
        scores = np.zeros(len(data))
        
        for i, value in enumerate(data):
            seasonal_idx = i % self.period
            expected_mean = self.model_data['seasonal_means'][seasonal_idx]
            expected_std = max(self.model_data['seasonal_stds'][seasonal_idx], 1e-6)
            
            scores[i] = abs(value - expected_mean) / expected_std
        
        return scores


class PredictiveModel:
    """Predictive model for forecasting metric values."""
    
    def __init__(self, model_type: str = "linear"):
        self.model_type = model_type
        self.model = None
        self.scaler = None
        self.trained = False
        self.accuracy_metrics = {}
        
        if SKLEARN_AVAILABLE:
            if model_type == "random_forest":
                self.model = RandomForestRegressor(n_estimators=50, random_state=42)
            else:
                # Simple linear regression fallback
                from sklearn.linear_model import LinearRegression
                self.model = LinearRegression()
            
            self.scaler = StandardScaler()
    
    def prepare_features(self, data: np.ndarray, timestamps: np.ndarray = None, 
                        window_size: int = 10) -> np.ndarray:
        """Prepare features for prediction."""
        features = []
        
        for i in range(window_size, len(data)):
            # Use previous values as features
            feature_vector = data[i-window_size:i].tolist()
            
            # Add time-based features if timestamps available
            if timestamps is not None and i < len(timestamps):
                dt = pd.to_datetime(timestamps[i])
                feature_vector.extend([
                    dt.hour,
                    dt.dayofweek,
                    dt.day,
                    dt.month
                ])
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def train(self, data: np.ndarray, timestamps: np.ndarray = None) -> None:
        """Train the predictive model."""
        if not SKLEARN_AVAILABLE or self.model is None or len(data) < 20:
            return
        
        try:
            # Prepare features and targets
            features = self.prepare_features(data, timestamps)
            if len(features) == 0:
                return
            
            targets = data[len(data) - len(features):]
            
            # Split data for validation
            X_train, X_test, y_train, y_test = train_test_split(
                features, targets, test_size=0.2, random_state=42
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train model
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.model.predict(X_test_scaled)
            self.accuracy_metrics = {
                'mse': mean_squared_error(y_test, y_pred),
                'mae': mean_absolute_error(y_test, y_pred),
                'rmse': np.sqrt(mean_squared_error(y_test, y_pred))
            }
            
            self.trained = True
            
        except Exception as e:
            logger.error(f"Error training predictive model: {e}")
    
    def predict(self, data: np.ndarray, timestamps: np.ndarray = None,
                horizon: int = 1) -> Tuple[np.ndarray, np.ndarray]:
        """Make predictions."""
        if not self.trained or not SKLEARN_AVAILABLE or self.model is None:
            return np.array([]), np.array([])
        
        try:
            predictions = []
            confidence_intervals = []
            
            current_data = data.copy()
            
            for _ in range(horizon):
                features = self.prepare_features(current_data, timestamps)
                if len(features) == 0:
                    break
                
                last_features = features[-1:] 
                scaled_features = self.scaler.transform(last_features)
                
                pred = self.model.predict(scaled_features)[0]
                predictions.append(pred)
                
                # Simple confidence interval based on training error
                error_std = self.accuracy_metrics.get('rmse', 1.0)
                confidence_intervals.append((pred - 2*error_std, pred + 2*error_std))
                
                # Update current_data for next prediction
                current_data = np.append(current_data, pred)
            
            return np.array(predictions), np.array(confidence_intervals)
            
        except Exception as e:
            logger.error(f"Error making predictions: {e}")
            return np.array([]), np.array([])


class PredictiveAlertEngine:
    """Main engine for predictive alerting and anomaly detection."""
    
    def __init__(self, db_path: str = "performance_monitoring.db"):
        self.db_path = db_path
        self.detectors: Dict[str, List[BaseAnomalyDetector]] = defaultdict(list)
        self.predictive_models: Dict[str, PredictiveModel] = {}
        self.metric_thresholds: Dict[str, Dict[str, float]] = {}
        self.alert_history = deque(maxlen=1000)
        self.training_data: Dict[str, List[float]] = defaultdict(list)
        self.running = False
        self._analysis_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the predictive alert engine."""
        try:
            await self._load_thresholds()
            await self._setup_default_detectors()
            logger.info("Predictive Alert Engine initialized")
        except Exception as e:
            logger.error(f"Failed to initialize predictive alert engine: {e}")
            raise
    
    async def _load_thresholds(self):
        """Load metric thresholds from database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT metric_name, threshold_type, value, operator
                    FROM metric_thresholds
                    WHERE enabled = 1
                """)
                
                rows = await cursor.fetchall()
                
                for row in rows:
                    metric_name, threshold_type, value, operator = row
                    if metric_name not in self.metric_thresholds:
                        self.metric_thresholds[metric_name] = {}
                    
                    self.metric_thresholds[metric_name][threshold_type] = {
                        'value': value,
                        'operator': operator
                    }
                    
        except Exception as e:
            logger.error(f"Error loading thresholds: {e}")
    
    async def _setup_default_detectors(self):
        """Setup default anomaly detectors for different metric types."""
        
        # System metrics - use multiple detectors
        system_metrics = ["cpu_usage_percent", "memory_usage_percent", "disk_usage_percent"]
        for metric in system_metrics:
            self.detectors[metric].extend([
                StatisticalAnomalyDetector("statistical", sensitivity=0.1),
                TrendAnomalyDetector("trend", sensitivity=0.1),
                SeasonalAnomalyDetector("seasonal", sensitivity=0.1, period=24)
            ])
            
            if SKLEARN_AVAILABLE:
                self.detectors[metric].append(
                    MLAnomalyDetector("isolation_forest", sensitivity=0.1)
                )
            
            self.predictive_models[metric] = PredictiveModel("linear")
        
        # API metrics - focus on performance patterns
        api_metrics = ["request_duration_avg_ms", "request_duration_p95_ms", "error_rate_percent"]
        for metric in api_metrics:
            self.detectors[metric].extend([
                StatisticalAnomalyDetector("statistical", sensitivity=0.05),
                TrendAnomalyDetector("trend", sensitivity=0.05)
            ])
            
            self.predictive_models[metric] = PredictiveModel("random_forest")
    
    async def start_monitoring(self):
        """Start the monitoring and analysis process."""
        if self.running:
            return
        
        self.running = True
        self._analysis_task = asyncio.create_task(self._analysis_loop())
        logger.info("Predictive alert monitoring started")
    
    async def stop_monitoring(self):
        """Stop the monitoring process."""
        if not self.running:
            return
        
        self.running = False
        if self._analysis_task:
            self._analysis_task.cancel()
            try:
                await self._analysis_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Predictive alert monitoring stopped")
    
    async def _analysis_loop(self):
        """Main analysis loop."""
        while self.running:
            try:
                await self._analyze_recent_metrics()
                await asyncio.sleep(60)  # Analyze every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in analysis loop: {e}")
                await asyncio.sleep(60)
    
    async def _analyze_recent_metrics(self):
        """Analyze recent metrics for anomalies and predictions."""
        try:
            # Get recent metrics from database
            recent_metrics = await self._get_recent_metrics()
            
            for metric_name, data_points in recent_metrics.items():
                if len(data_points) < 10:  # Need minimum data points
                    continue
                
                # Prepare data
                values = np.array([point['value'] for point in data_points])
                timestamps = np.array([point['timestamp'] for point in data_points])
                
                # Update training data
                self.training_data[metric_name].extend(values.tolist())
                if len(self.training_data[metric_name]) > 1000:
                    self.training_data[metric_name] = self.training_data[metric_name][-1000:]
                
                # Train detectors if we have enough data
                if len(self.training_data[metric_name]) >= 50:
                    await self._retrain_detectors(metric_name)
                
                # Perform anomaly detection
                anomalies = await self._detect_anomalies(metric_name, values, timestamps)
                
                # Perform predictive analysis
                predictions = await self._generate_predictions(metric_name, values, timestamps)
                
                # Generate alerts
                await self._process_anomalies_and_predictions(metric_name, anomalies, predictions)
                
        except Exception as e:
            logger.error(f"Error analyzing recent metrics: {e}")
    
    async def _get_recent_metrics(self, hours: int = 2) -> Dict[str, List[Dict]]:
        """Get recent metrics from database."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT name, value, timestamp
                    FROM metric_points
                    WHERE timestamp > ?
                    ORDER BY name, timestamp
                """, (cutoff_time.isoformat(),))
                
                rows = await cursor.fetchall()
                
                metrics = defaultdict(list)
                for row in rows:
                    name, value, timestamp = row
                    metrics[name].append({
                        'value': value,
                        'timestamp': timestamp
                    })
                
                return dict(metrics)
                
        except Exception as e:
            logger.error(f"Error getting recent metrics: {e}")
            return {}
    
    async def _retrain_detectors(self, metric_name: str):
        """Retrain anomaly detectors for a specific metric."""
        try:
            if metric_name not in self.detectors:
                return
            
            training_data = np.array(self.training_data[metric_name])
            
            for detector in self.detectors[metric_name]:
                detector.train(training_data)
            
            # Train predictive model
            if metric_name in self.predictive_models:
                self.predictive_models[metric_name].train(training_data)
                
        except Exception as e:
            logger.error(f"Error retraining detectors for {metric_name}: {e}")
    
    async def _detect_anomalies(self, metric_name: str, values: np.ndarray, 
                              timestamps: np.ndarray) -> List[AnomalyDetectionResult]:
        """Detect anomalies in metric data."""
        anomalies = []
        
        try:
            if metric_name not in self.detectors:
                return anomalies
            
            detector_results = {}
            
            # Run all detectors
            for detector in self.detectors[metric_name]:
                if detector.trained:
                    anomaly_mask = detector.detect(values, timestamps)
                    anomaly_scores = detector.get_anomaly_score(values)
                    detector_results[detector.name] = {
                        'mask': anomaly_mask,
                        'scores': anomaly_scores
                    }
            
            # Aggregate detector results
            for i, (value, timestamp) in enumerate(zip(values, timestamps)):
                anomaly_detected = False
                max_confidence = 0.0
                best_detector = None
                
                for detector_name, results in detector_results.items():
                    if i < len(results['mask']) and results['mask'][i]:
                        anomaly_detected = True
                        confidence = results['scores'][i] if i < len(results['scores']) else 1.0
                        
                        if confidence > max_confidence:
                            max_confidence = confidence
                            best_detector = detector_name
                
                if anomaly_detected:
                    # Determine severity based on confidence and threshold
                    severity = self._calculate_severity(metric_name, value, max_confidence)
                    
                    # Calculate expected range
                    expected_range = self._calculate_expected_range(metric_name, value)
                    
                    anomaly = AnomalyDetectionResult(
                        metric_name=metric_name,
                        timestamp=pd.to_datetime(timestamp),
                        value=value,
                        anomaly_type=AnomalyType.POINT_ANOMALY,  # Could be more sophisticated
                        severity=severity,
                        confidence=max_confidence,
                        expected_range=expected_range,
                        deviation_score=max_confidence,
                        context={'detector': best_detector},
                        metadata={'all_detector_scores': {k: v['scores'][i] 
                                                        for k, v in detector_results.items() 
                                                        if i < len(v['scores'])}}
                    )
                    
                    anomalies.append(anomaly)
            
        except Exception as e:
            logger.error(f"Error detecting anomalies for {metric_name}: {e}")
        
        return anomalies
    
    async def _generate_predictions(self, metric_name: str, values: np.ndarray,
                                  timestamps: np.ndarray) -> List[PredictionResult]:
        """Generate predictions for metric values."""
        predictions = []
        
        try:
            if metric_name not in self.predictive_models:
                return predictions
            
            model = self.predictive_models[metric_name]
            if not model.trained:
                return predictions
            
            # Generate predictions for next 6 time periods
            pred_values, conf_intervals = model.predict(values, timestamps, horizon=6)
            
            for i, (pred_value, conf_interval) in enumerate(zip(pred_values, conf_intervals)):
                # Calculate time for prediction
                prediction_time = pd.to_datetime(timestamps[-1]) + timedelta(hours=i+1)
                
                # Check threshold breach probability
                threshold_breach_prob = 0.0
                time_to_threshold = None
                
                if metric_name in self.metric_thresholds:
                    threshold_breach_prob, time_to_threshold = self._calculate_threshold_breach_probability(
                        metric_name, pred_value, conf_interval
                    )
                
                prediction = PredictionResult(
                    metric_name=metric_name,
                    prediction_time=prediction_time,
                    predicted_value=pred_value,
                    confidence_interval=conf_interval,
                    probability_threshold_breach=threshold_breach_prob,
                    time_to_threshold=time_to_threshold,
                    model_accuracy=1.0 - model.accuracy_metrics.get('mae', 0.0),
                    prediction_horizon=timedelta(hours=i+1),
                    metadata={'model_type': model.model_type}
                )
                
                predictions.append(prediction)
                
        except Exception as e:
            logger.error(f"Error generating predictions for {metric_name}: {e}")
        
        return predictions
    
    def _calculate_severity(self, metric_name: str, value: float, confidence: float) -> AlertSeverity:
        """Calculate alert severity based on value and confidence."""
        # Check if we have thresholds for this metric
        if metric_name in self.metric_thresholds:
            thresholds = self.metric_thresholds[metric_name]
            
            if 'critical' in thresholds:
                threshold = thresholds['critical']
                if self._check_threshold(value, threshold['value'], threshold['operator']):
                    return AlertSeverity.EMERGENCY
            
            if 'warning' in thresholds:
                threshold = thresholds['warning']
                if self._check_threshold(value, threshold['value'], threshold['operator']):
                    return AlertSeverity.CRITICAL if confidence > 0.8 else AlertSeverity.WARNING
        
        # Fallback to confidence-based severity
        if confidence > 0.9:
            return AlertSeverity.CRITICAL
        elif confidence > 0.7:
            return AlertSeverity.WARNING
        else:
            return AlertSeverity.INFO
    
    def _check_threshold(self, value: float, threshold: float, operator: str) -> bool:
        """Check if value meets threshold condition."""
        if operator == 'gt':
            return value > threshold
        elif operator == 'lt':
            return value < threshold
        elif operator == 'gte':
            return value >= threshold
        elif operator == 'lte':
            return value <= threshold
        elif operator == 'eq':
            return abs(value - threshold) < 1e-6
        elif operator == 'ne':
            return abs(value - threshold) >= 1e-6
        return False
    
    def _calculate_expected_range(self, metric_name: str, value: float) -> Tuple[float, float]:
        """Calculate expected range for the metric."""
        if metric_name in self.training_data and len(self.training_data[metric_name]) > 10:
            data = np.array(self.training_data[metric_name])
            mean = np.mean(data)
            std = np.std(data)
            return (mean - 2*std, mean + 2*std)
        
        # Fallback range
        return (value * 0.8, value * 1.2)
    
    def _calculate_threshold_breach_probability(self, metric_name: str, pred_value: float,
                                              conf_interval: Tuple[float, float]) -> Tuple[float, Optional[timedelta]]:
        """Calculate probability of threshold breach."""
        if metric_name not in self.metric_thresholds:
            return 0.0, None
        
        thresholds = self.metric_thresholds[metric_name]
        max_prob = 0.0
        
        for threshold_type, threshold_config in thresholds.items():
            threshold_value = threshold_config['value']
            operator = threshold_config['operator']
            
            # Simple probability calculation based on confidence interval
            if operator in ['gt', 'gte']:
                if pred_value > threshold_value:
                    prob = 0.8  # High probability if prediction exceeds threshold
                elif conf_interval[1] > threshold_value:
                    prob = 0.4  # Medium probability if upper bound exceeds threshold
                else:
                    prob = 0.1  # Low probability
            elif operator in ['lt', 'lte']:
                if pred_value < threshold_value:
                    prob = 0.8
                elif conf_interval[0] < threshold_value:
                    prob = 0.4
                else:
                    prob = 0.1
            else:
                prob = 0.1
            
            max_prob = max(max_prob, prob)
        
        # Estimate time to threshold breach (simplified)
        time_to_threshold = timedelta(hours=1) if max_prob > 0.5 else None
        
        return max_prob, time_to_threshold
    
    async def _process_anomalies_and_predictions(self, metric_name: str,
                                               anomalies: List[AnomalyDetectionResult],
                                               predictions: List[PredictionResult]):
        """Process anomalies and predictions to generate alerts."""
        try:
            # Store anomalies
            for anomaly in anomalies:
                await self._store_alert(anomaly)
            
            # Process predictions for potential future alerts
            for prediction in predictions:
                if prediction.probability_threshold_breach > 0.6:
                    # Create predictive alert
                    await self._store_predictive_alert(prediction)
                    
        except Exception as e:
            logger.error(f"Error processing anomalies and predictions: {e}")
    
    async def _store_alert(self, anomaly: AnomalyDetectionResult):
        """Store anomaly alert in database."""
        try:
            alert_id = f"{anomaly.metric_name}_{int(anomaly.timestamp.timestamp())}"
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO performance_alerts (
                        alert_id, rule_name, alert_type, severity, confidence,
                        description, metric_name, current_value, threshold_value,
                        first_occurrence, last_occurrence, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    f"{anomaly.anomaly_type.value}_detection",
                    anomaly.anomaly_type.value,
                    anomaly.severity.value,
                    anomaly.confidence,
                    f"Anomaly detected in {anomaly.metric_name}: {anomaly.value:.2f}",
                    anomaly.metric_name,
                    anomaly.value,
                    None,
                    anomaly.timestamp.isoformat(),
                    anomaly.timestamp.isoformat(),
                    json.dumps(anomaly.metadata)
                ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
    
    async def _store_predictive_alert(self, prediction: PredictionResult):
        """Store predictive alert in database."""
        try:
            alert_id = f"predictive_{prediction.metric_name}_{int(prediction.prediction_time.timestamp())}"
            
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO performance_alerts (
                        alert_id, rule_name, alert_type, severity, confidence,
                        description, metric_name, current_value, threshold_value,
                        first_occurrence, last_occurrence, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id,
                    "predictive_threshold_breach",
                    "predictive",
                    "warning",
                    prediction.probability_threshold_breach,
                    f"Predicted threshold breach for {prediction.metric_name} at {prediction.prediction_time}",
                    prediction.metric_name,
                    prediction.predicted_value,
                    None,
                    prediction.prediction_time.isoformat(),
                    prediction.prediction_time.isoformat(),
                    json.dumps(prediction.metadata)
                ))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing predictive alert: {e}")
    
    async def get_active_alerts(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get active alerts."""
        try:
            query = """
                SELECT alert_id, rule_name, alert_type, severity, description,
                       metric_name, current_value, first_occurrence, occurrence_count
                FROM performance_alerts
                WHERE status = 'open'
            """
            params = []
            
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            
            query += " ORDER BY first_occurrence DESC"
            
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(query, params)
                rows = await cursor.fetchall()
                
                return [
                    {
                        'alert_id': row[0],
                        'rule_name': row[1],
                        'alert_type': row[2],
                        'severity': row[3],
                        'description': row[4],
                        'metric_name': row[5],
                        'current_value': row[6],
                        'first_occurrence': row[7],
                        'occurrence_count': row[8]
                    }
                    for row in rows
                ]
                
        except Exception as e:
            logger.error(f"Error getting active alerts: {e}")
            return []
    
    async def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    UPDATE performance_alerts
                    SET status = 'acknowledged', acknowledged_by = ?, acknowledged_at = ?
                    WHERE alert_id = ?
                """, (user, datetime.now(timezone.utc).isoformat(), alert_id))
                
                await db.commit()
                return True
                
        except Exception as e:
            logger.error(f"Error acknowledging alert: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown the predictive alert engine."""
        await self.stop_monitoring()
        logger.info("Predictive Alert Engine shutdown complete")