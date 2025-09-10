"""
Behavioral Analytics and Anomaly Detection Engine

Advanced machine learning and statistical analysis for detecting unusual patterns
and behaviors that may indicate security threats.
"""

import asyncio
import logging
import numpy as np
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import math
import statistics
import sqlite3
import aiosqlite
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import pandas as pd

from .indicators import ThreatLevel

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of anomalies detected."""
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    VOLUMETRIC = "volumetric"
    PATTERN = "pattern"
    OUTLIER = "outlier"


@dataclass
class Anomaly:
    """Represents a detected anomaly."""
    anomaly_id: str
    anomaly_type: AnomalyType
    description: str
    confidence: float
    severity: ThreatLevel
    score: float
    baseline_value: Optional[float] = None
    observed_value: Optional[float] = None
    threshold: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "analytics_engine"
    affected_entities: List[str] = field(default_factory=list)


@dataclass
class UserBehaviorProfile:
    """User behavior baseline profile."""
    user_id: str
    login_times: List[float] = field(default_factory=list)  # Hour of day
    login_locations: Set[str] = field(default_factory=set)  # IP addresses
    typical_endpoints: Set[str] = field(default_factory=set)
    session_duration_avg: float = 0.0
    session_duration_std: float = 0.0
    request_rate_avg: float = 0.0
    request_rate_std: float = 0.0
    data_access_patterns: Dict[str, int] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sample_count: int = 0


class StatisticalAnalyzer:
    """Statistical analysis for anomaly detection."""
    
    def __init__(self, window_size: int = 1000):
        """Initialize statistical analyzer."""
        self.window_size = window_size
        self.data_windows: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))
        self.statistics_cache: Dict[str, Dict[str, float]] = {}
    
    def add_datapoint(self, metric_name: str, value: float):
        """Add a datapoint to the statistical window."""
        self.data_windows[metric_name].append(value)
        
        # Update statistics if we have enough data
        if len(self.data_windows[metric_name]) >= 10:
            self._update_statistics(metric_name)
    
    def _update_statistics(self, metric_name: str):
        """Update statistical measures for a metric."""
        data = list(self.data_windows[metric_name])
        
        try:
            self.statistics_cache[metric_name] = {
                'mean': statistics.mean(data),
                'median': statistics.median(data),
                'stdev': statistics.stdev(data) if len(data) > 1 else 0,
                'min': min(data),
                'max': max(data),
                'q25': np.percentile(data, 25),
                'q75': np.percentile(data, 75)
            }
        except Exception as e:
            logger.error(f"Error updating statistics for {metric_name}: {e}")
    
    def detect_statistical_anomalies(self, metric_name: str, value: float) -> List[Anomaly]:
        """Detect statistical anomalies using various methods."""
        anomalies = []
        
        if metric_name not in self.statistics_cache:
            return anomalies
        
        stats = self.statistics_cache[metric_name]
        
        # Z-score anomaly detection
        if stats['stdev'] > 0:
            z_score = abs(value - stats['mean']) / stats['stdev']
            
            if z_score > 3:  # 3 standard deviations
                anomalies.append(Anomaly(
                    anomaly_id=f"zscore_{metric_name}_{int(datetime.now().timestamp())}",
                    anomaly_type=AnomalyType.STATISTICAL,
                    description=f"Statistical outlier detected for {metric_name}",
                    confidence=min(0.95, z_score / 5),
                    severity=ThreatLevel.MEDIUM if z_score > 4 else ThreatLevel.LOW,
                    score=z_score,
                    baseline_value=stats['mean'],
                    observed_value=value,
                    threshold=3.0,
                    details={'z_score': z_score, 'method': 'z_score'}
                ))
        
        # IQR-based anomaly detection
        iqr = stats['q75'] - stats['q25']
        lower_bound = stats['q25'] - 1.5 * iqr
        upper_bound = stats['q75'] + 1.5 * iqr
        
        if value < lower_bound or value > upper_bound:
            distance_from_bound = max(lower_bound - value, value - upper_bound, 0)
            score = distance_from_bound / (iqr if iqr > 0 else 1)
            
            anomalies.append(Anomaly(
                anomaly_id=f"iqr_{metric_name}_{int(datetime.now().timestamp())}",
                anomaly_type=AnomalyType.OUTLIER,
                description=f"IQR-based outlier detected for {metric_name}",
                confidence=min(0.9, score / 3),
                severity=ThreatLevel.MEDIUM if score > 2 else ThreatLevel.LOW,
                score=score,
                baseline_value=stats['median'],
                observed_value=value,
                threshold=1.5,
                details={
                    'iqr': iqr,
                    'lower_bound': lower_bound,
                    'upper_bound': upper_bound,
                    'method': 'iqr'
                }
            ))
        
        return anomalies


class BehavioralAnalyzer:
    """Behavioral analysis for user and system activity."""
    
    def __init__(self):
        """Initialize behavioral analyzer."""
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        self.ml_models: Dict[str, Any] = {}
        self.feature_scalers: Dict[str, StandardScaler] = {}
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize machine learning models."""
        # Isolation Forest for anomaly detection
        self.ml_models['isolation_forest'] = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # DBSCAN for clustering
        self.ml_models['dbscan'] = DBSCAN(eps=0.5, min_samples=5)
        
        # Feature scaler
        self.feature_scalers['main'] = StandardScaler()
    
    def update_user_profile(self, user_id: str, activity_data: Dict[str, Any]):
        """Update user behavioral profile with new activity."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserBehaviorProfile(user_id=user_id)
        
        profile = self.user_profiles[user_id]
        
        try:
            # Update login time patterns
            if 'login_time' in activity_data:
                login_hour = datetime.fromisoformat(activity_data['login_time']).hour
                profile.login_times.append(login_hour)
                if len(profile.login_times) > 100:  # Keep recent history
                    profile.login_times.pop(0)
            
            # Update location patterns
            if 'source_ip' in activity_data:
                profile.login_locations.add(activity_data['source_ip'])
            
            # Update endpoint access patterns
            if 'endpoint' in activity_data:
                profile.typical_endpoints.add(activity_data['endpoint'])
            
            # Update session patterns
            if 'session_duration' in activity_data:
                duration = activity_data['session_duration']
                # Running average calculation
                profile.session_duration_avg = (
                    (profile.session_duration_avg * profile.sample_count + duration) / 
                    (profile.sample_count + 1)
                )
                
                # Update standard deviation
                if profile.sample_count > 0:
                    variance = ((profile.session_duration_std ** 2) * profile.sample_count + 
                               (duration - profile.session_duration_avg) ** 2) / (profile.sample_count + 1)
                    profile.session_duration_std = math.sqrt(variance)
            
            # Update data access patterns
            if 'data_accessed' in activity_data:
                data_type = activity_data['data_accessed']
                profile.data_access_patterns[data_type] = profile.data_access_patterns.get(data_type, 0) + 1
            
            profile.sample_count += 1
            profile.last_updated = datetime.now(timezone.utc)
            
        except Exception as e:
            logger.error(f"Error updating user profile for {user_id}: {e}")
    
    def detect_behavioral_anomalies(self, user_id: str, current_activity: Dict[str, Any]) -> List[Anomaly]:
        """Detect behavioral anomalies for a user."""
        anomalies = []
        
        if user_id not in self.user_profiles:
            return anomalies
        
        profile = self.user_profiles[user_id]
        
        if profile.sample_count < 10:  # Need baseline data
            return anomalies
        
        try:
            # Time-based anomaly detection
            if 'timestamp' in current_activity:
                activity_hour = datetime.fromisoformat(current_activity['timestamp']).hour
                
                # Check if login time is unusual
                if profile.login_times:
                    typical_hours = set(profile.login_times)
                    if activity_hour not in typical_hours:
                        # Calculate how unusual this time is
                        time_distances = [min(abs(activity_hour - t), abs(activity_hour - t + 24), abs(activity_hour - t - 24)) 
                                        for t in typical_hours]
                        min_distance = min(time_distances)
                        
                        if min_distance > 2:  # More than 2 hours from typical times
                            anomalies.append(Anomaly(
                                anomaly_id=f"time_anomaly_{user_id}_{int(datetime.now().timestamp())}",
                                anomaly_type=AnomalyType.TEMPORAL,
                                description=f"Unusual login time for user {user_id}",
                                confidence=min(0.8, min_distance / 12),
                                severity=ThreatLevel.MEDIUM if min_distance > 6 else ThreatLevel.LOW,
                                score=min_distance,
                                details={'typical_hours': list(typical_hours), 'current_hour': activity_hour}
                            ))
            
            # Location-based anomaly detection
            if 'source_ip' in current_activity:
                source_ip = current_activity['source_ip']
                
                if source_ip not in profile.login_locations:
                    # New location detected
                    anomalies.append(Anomaly(
                        anomaly_id=f"location_anomaly_{user_id}_{int(datetime.now().timestamp())}",
                        anomaly_type=AnomalyType.BEHAVIORAL,
                        description=f"Login from new location for user {user_id}",
                        confidence=0.7,
                        severity=ThreatLevel.MEDIUM,
                        score=1.0,
                        details={
                            'new_location': source_ip,
                            'known_locations': list(profile.login_locations)
                        }
                    ))
            
            # Session duration anomaly detection
            if 'session_duration' in current_activity:
                duration = current_activity['session_duration']
                
                if profile.session_duration_std > 0:
                    z_score = abs(duration - profile.session_duration_avg) / profile.session_duration_std
                    
                    if z_score > 3:
                        anomalies.append(Anomaly(
                            anomaly_id=f"session_anomaly_{user_id}_{int(datetime.now().timestamp())}",
                            anomaly_type=AnomalyType.BEHAVIORAL,
                            description=f"Unusual session duration for user {user_id}",
                            confidence=min(0.9, z_score / 5),
                            severity=ThreatLevel.MEDIUM if z_score > 4 else ThreatLevel.LOW,
                            score=z_score,
                            baseline_value=profile.session_duration_avg,
                            observed_value=duration,
                            details={'z_score': z_score}
                        ))
            
            # Data access pattern anomaly detection
            if 'endpoint' in current_activity:
                endpoint = current_activity['endpoint']
                
                if endpoint not in profile.typical_endpoints:
                    # Accessing unusual endpoint
                    anomalies.append(Anomaly(
                        anomaly_id=f"endpoint_anomaly_{user_id}_{int(datetime.now().timestamp())}",
                        anomaly_type=AnomalyType.PATTERN,
                        description=f"Access to unusual endpoint for user {user_id}",
                        confidence=0.6,
                        severity=ThreatLevel.LOW,
                        score=1.0,
                        details={
                            'new_endpoint': endpoint,
                            'typical_endpoints': list(profile.typical_endpoints)
                        }
                    ))
            
        except Exception as e:
            logger.error(f"Error detecting behavioral anomalies for {user_id}: {e}")
        
        return anomalies
    
    def detect_ml_anomalies(self, features: List[Dict[str, Any]]) -> List[Anomaly]:
        """Detect anomalies using machine learning models."""
        anomalies = []
        
        if len(features) < 10:  # Need minimum data
            return anomalies
        
        try:
            # Prepare feature matrix
            feature_matrix = self._prepare_feature_matrix(features)
            
            if feature_matrix is None or len(feature_matrix) == 0:
                return anomalies
            
            # Scale features
            scaled_features = self.feature_scalers['main'].fit_transform(feature_matrix)
            
            # Isolation Forest anomaly detection
            anomaly_scores = self.ml_models['isolation_forest'].fit_predict(scaled_features)
            anomaly_score_values = self.ml_models['isolation_forest'].score_samples(scaled_features)
            
            for i, (score, score_value) in enumerate(zip(anomaly_scores, anomaly_score_values)):
                if score == -1:  # Anomaly detected
                    confidence = min(0.9, abs(score_value) * 2)
                    
                    anomalies.append(Anomaly(
                        anomaly_id=f"ml_anomaly_{i}_{int(datetime.now().timestamp())}",
                        anomaly_type=AnomalyType.OUTLIER,
                        description="Machine learning based anomaly detection",
                        confidence=confidence,
                        severity=ThreatLevel.MEDIUM if confidence > 0.7 else ThreatLevel.LOW,
                        score=abs(score_value),
                        details={
                            'method': 'isolation_forest',
                            'feature_index': i,
                            'anomaly_score': score_value
                        }
                    ))
            
            # DBSCAN clustering for pattern detection
            cluster_labels = self.ml_models['dbscan'].fit_predict(scaled_features)
            
            # Points labeled as -1 are outliers
            for i, label in enumerate(cluster_labels):
                if label == -1:
                    anomalies.append(Anomaly(
                        anomaly_id=f"cluster_anomaly_{i}_{int(datetime.now().timestamp())}",
                        anomaly_type=AnomalyType.PATTERN,
                        description="Clustering-based anomaly detection",
                        confidence=0.6,
                        severity=ThreatLevel.LOW,
                        score=1.0,
                        details={
                            'method': 'dbscan',
                            'feature_index': i,
                            'cluster_label': label
                        }
                    ))
            
        except Exception as e:
            logger.error(f"Error in ML anomaly detection: {e}")
        
        return anomalies
    
    def _prepare_feature_matrix(self, features: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        """Prepare feature matrix for ML models."""
        try:
            # Extract numerical features
            feature_names = ['hour', 'request_count', 'response_time', 'data_size', 'error_count']
            
            feature_matrix = []
            for feature_dict in features:
                row = []
                for feature_name in feature_names:
                    value = feature_dict.get(feature_name, 0)
                    # Convert to float if possible
                    try:
                        row.append(float(value))
                    except (ValueError, TypeError):
                        row.append(0.0)
                
                feature_matrix.append(row)
            
            return np.array(feature_matrix) if feature_matrix else None
            
        except Exception as e:
            logger.error(f"Error preparing feature matrix: {e}")
            return None


class AnomalyDetector:
    """Main anomaly detection coordinator."""
    
    def __init__(self, db_path: str = "anomalies.db"):
        """Initialize anomaly detector."""
        self.db_path = db_path
        self.statistical_analyzer = StatisticalAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.detected_anomalies: Dict[str, Anomaly] = {}
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize the anomaly detector."""
        try:
            await self._create_database()
            logger.info("Anomaly Detector initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Anomaly Detector: {e}")
            raise
    
    async def _create_database(self):
        """Create anomalies database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    anomaly_id TEXT PRIMARY KEY,
                    anomaly_type TEXT NOT NULL,
                    description TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    score REAL NOT NULL,
                    baseline_value REAL,
                    observed_value REAL,
                    threshold_value REAL,
                    details TEXT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    affected_entities TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("CREATE INDEX IF NOT EXISTS idx_anomaly_type ON anomalies(anomaly_type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_severity ON anomalies(severity)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON anomalies(timestamp)")
            
            await db.commit()
    
    async def detect_anomalies(self, event: Dict[str, Any]) -> List[Anomaly]:
        """Main anomaly detection method."""
        all_anomalies = []
        
        try:
            # Extract relevant metrics from event
            metrics = self._extract_metrics_from_event(event)
            
            # Statistical anomaly detection
            for metric_name, value in metrics.items():
                self.statistical_analyzer.add_datapoint(metric_name, value)
                statistical_anomalies = self.statistical_analyzer.detect_statistical_anomalies(metric_name, value)
                all_anomalies.extend(statistical_anomalies)
            
            # Behavioral anomaly detection
            user_id = event.get('user_id') or event.get('username')
            if user_id:
                # Update user profile
                self.behavioral_analyzer.update_user_profile(user_id, event)
                
                # Detect behavioral anomalies
                behavioral_anomalies = self.behavioral_analyzer.detect_behavioral_anomalies(user_id, event)
                all_anomalies.extend(behavioral_anomalies)
            
            # Store detected anomalies
            async with self._lock:
                for anomaly in all_anomalies:
                    self.detected_anomalies[anomaly.anomaly_id] = anomaly
                    await self._save_anomaly_to_db(anomaly)
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
        
        return all_anomalies
    
    def _extract_metrics_from_event(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical metrics from an event."""
        metrics = {}
        
        # Time-based metrics
        if 'timestamp' in event:
            try:
                timestamp = datetime.fromisoformat(event['timestamp'])
                metrics['hour_of_day'] = timestamp.hour
                metrics['day_of_week'] = timestamp.weekday()
            except Exception:
                pass
        
        # Request metrics
        if 'response_time' in event:
            try:
                metrics['response_time'] = float(event['response_time'])
            except (ValueError, TypeError):
                pass
        
        if 'status_code' in event:
            try:
                metrics['status_code'] = float(event['status_code'])
            except (ValueError, TypeError):
                pass
        
        if 'request_size' in event:
            try:
                metrics['request_size'] = float(event['request_size'])
            except (ValueError, TypeError):
                pass
        
        if 'response_size' in event:
            try:
                metrics['response_size'] = float(event['response_size'])
            except (ValueError, TypeError):
                pass
        
        # User activity metrics
        if 'session_duration' in event:
            try:
                metrics['session_duration'] = float(event['session_duration'])
            except (ValueError, TypeError):
                pass
        
        if 'request_count' in event:
            try:
                metrics['request_count'] = float(event['request_count'])
            except (ValueError, TypeError):
                pass
        
        return metrics
    
    async def _save_anomaly_to_db(self, anomaly: Anomaly):
        """Save anomaly to database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO anomalies (
                        anomaly_id, anomaly_type, description, confidence, severity,
                        score, baseline_value, observed_value, threshold_value,
                        details, timestamp, source, affected_entities
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    anomaly.anomaly_id,
                    anomaly.anomaly_type.value,
                    anomaly.description,
                    anomaly.confidence,
                    anomaly.severity.value,
                    anomaly.score,
                    anomaly.baseline_value,
                    anomaly.observed_value,
                    anomaly.threshold,
                    json.dumps(anomaly.details),
                    anomaly.timestamp.isoformat(),
                    anomaly.source,
                    json.dumps(anomaly.affected_entities)
                ))
                await db.commit()
        except Exception as e:
            logger.error(f"Error saving anomaly to database: {e}")
    
    async def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get summary of detected anomalies."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Count by type
                async with db.execute("SELECT anomaly_type, COUNT(*) FROM anomalies GROUP BY anomaly_type") as cursor:
                    type_counts = dict(await cursor.fetchall())
                
                # Count by severity
                async with db.execute("SELECT severity, COUNT(*) FROM anomalies GROUP BY severity") as cursor:
                    severity_counts = dict(await cursor.fetchall())
                
                # Recent anomalies (last 24 hours)
                yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
                async with db.execute("SELECT COUNT(*) FROM anomalies WHERE timestamp > ?", (yesterday,)) as cursor:
                    recent_count = (await cursor.fetchone())[0]
                
                return {
                    'total_anomalies': len(self.detected_anomalies),
                    'type_distribution': type_counts,
                    'severity_distribution': severity_counts,
                    'recent_anomalies_24h': recent_count,
                    'active_anomalies': len(self.detected_anomalies)
                }
        except Exception as e:
            logger.error(f"Error getting anomaly summary: {e}")
            return {}
    
    async def shutdown(self):
        """Shutdown the anomaly detector."""
        logger.info("Shutting down Anomaly Detector")


class BehavioralAnalytics:
    """High-level behavioral analytics coordinator."""
    
    def __init__(self):
        """Initialize behavioral analytics."""
        self.anomaly_detector = AnomalyDetector()
        self.event_buffer = deque(maxlen=1000)  # Buffer recent events for batch analysis
    
    async def initialize(self):
        """Initialize behavioral analytics."""
        await self.anomaly_detector.initialize()
        
        # Start batch analysis task
        asyncio.create_task(self._batch_analysis_task())
        
        logger.info("Behavioral Analytics initialized")
    
    async def analyze_event(self, event: Dict[str, Any]) -> List[Anomaly]:
        """Analyze a single event for anomalies."""
        # Add to buffer for batch analysis
        self.event_buffer.append(event)
        
        # Perform real-time analysis
        return await self.anomaly_detector.detect_anomalies(event)
    
    async def _batch_analysis_task(self):
        """Background task for batch analysis of events."""
        while True:
            try:
                if len(self.event_buffer) >= 50:  # Minimum batch size
                    # Convert events to feature format
                    features = []
                    for event in list(self.event_buffer):
                        feature_dict = self._event_to_features(event)
                        if feature_dict:
                            features.append(feature_dict)
                    
                    # Perform ML-based anomaly detection
                    if features:
                        ml_anomalies = self.anomaly_detector.behavioral_analyzer.detect_ml_anomalies(features)
                        
                        # Store ML anomalies
                        async with self.anomaly_detector._lock:
                            for anomaly in ml_anomalies:
                                self.anomaly_detector.detected_anomalies[anomaly.anomaly_id] = anomaly
                                await self.anomaly_detector._save_anomaly_to_db(anomaly)
                
                await asyncio.sleep(60)  # Run every minute
                
            except Exception as e:
                logger.error(f"Error in batch analysis task: {e}")
                await asyncio.sleep(60)
    
    def _event_to_features(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert event to feature dictionary for ML analysis."""
        try:
            features = {}
            
            # Time features
            if 'timestamp' in event:
                timestamp = datetime.fromisoformat(event['timestamp'])
                features['hour'] = timestamp.hour
                features['day_of_week'] = timestamp.weekday()
            else:
                features['hour'] = 0
                features['day_of_week'] = 0
            
            # Request features
            features['request_count'] = 1  # Each event represents one request
            features['response_time'] = event.get('response_time', 0)
            features['data_size'] = event.get('response_size', 0)
            features['error_count'] = 1 if event.get('status_code', 200) >= 400 else 0
            
            return features
            
        except Exception as e:
            logger.error(f"Error converting event to features: {e}")
            return None
    
    async def get_analytics_summary(self) -> Dict[str, Any]:
        """Get behavioral analytics summary."""
        anomaly_summary = await self.anomaly_detector.get_anomaly_summary()
        
        return {
            'anomaly_detection': anomaly_summary,
            'user_profiles_count': len(self.anomaly_detector.behavioral_analyzer.user_profiles),
            'events_analyzed': len(self.event_buffer),
            'batch_analysis_enabled': True
        }
    
    async def shutdown(self):
        """Shutdown behavioral analytics."""
        await self.anomaly_detector.shutdown()
        logger.info("Behavioral Analytics shutdown complete")