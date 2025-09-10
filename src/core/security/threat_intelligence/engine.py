"""
Core Threat Intelligence Engine

Central coordination system for all threat intelligence activities including
detection, analysis, and response coordination.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from collections import defaultdict, deque

from .indicators import ThreatIndicatorManager, ThreatIndicator, ThreatLevel
from .analytics import BehavioralAnalytics, AnomalyDetector
from .monitoring import AdvancedSecurityMonitor, SecurityEventProcessor
from .response import AutomatedThreatResponse, IncidentManager
from .feeds import ThreatFeedManager
from .forensics import ForensicsCollector

logger = logging.getLogger(__name__)


class ThreatIntelligenceStatus(Enum):
    """Status of the threat intelligence engine."""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


@dataclass
class ThreatContext:
    """Context information for a detected threat."""
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    threat_type: str = ""
    source: str = ""
    confidence: float = 0.0
    severity: ThreatLevel = ThreatLevel.LOW
    indicators: List[ThreatIndicator] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    count: int = 1
    related_incidents: List[str] = field(default_factory=list)


@dataclass
class EngineMetrics:
    """Metrics for the threat intelligence engine."""
    threats_detected: int = 0
    threats_blocked: int = 0
    false_positives: int = 0
    indicators_processed: int = 0
    feed_updates: int = 0
    incidents_created: int = 0
    uptime_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_feed_update: Optional[datetime] = None
    processing_latency_ms: List[float] = field(default_factory=list)


class ThreatIntelligenceEngine:
    """
    Core threat intelligence engine that coordinates all security monitoring,
    detection, and response activities.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the threat intelligence engine."""
        self.config = config or {}
        self.status = ThreatIntelligenceStatus.INITIALIZING
        self.metrics = EngineMetrics()
        
        # Active threat contexts
        self.active_threats: Dict[str, ThreatContext] = {}
        self.threat_history = deque(maxlen=10000)  # Keep recent threat history
        
        # Component managers
        self.indicator_manager = ThreatIndicatorManager()
        self.behavioral_analytics = BehavioralAnalytics()
        self.anomaly_detector = AnomalyDetector()
        self.security_monitor = AdvancedSecurityMonitor()
        self.event_processor = SecurityEventProcessor()
        self.threat_response = AutomatedThreatResponse()
        self.incident_manager = IncidentManager()
        self.feed_manager = ThreatFeedManager()
        self.forensics_collector = ForensicsCollector()
        
        # Event handlers and callbacks
        self.threat_handlers: List[Callable] = []
        self.incident_handlers: List[Callable] = []
        
        # Processing queues
        self.detection_queue = asyncio.Queue()
        self.response_queue = asyncio.Queue()
        
        logger.info("Threat Intelligence Engine initialized")
    
    async def initialize(self) -> bool:
        """Initialize all components of the threat intelligence engine."""
        try:
            logger.info("Starting threat intelligence engine initialization")
            
            # Initialize all components
            await self.indicator_manager.initialize()
            await self.behavioral_analytics.initialize()
            await self.anomaly_detector.initialize()
            await self.security_monitor.initialize()
            await self.event_processor.initialize()
            await self.threat_response.initialize()
            await self.incident_manager.initialize()
            await self.feed_manager.initialize()
            await self.forensics_collector.initialize()
            
            # Start background tasks
            asyncio.create_task(self._detection_processor())
            asyncio.create_task(self._response_processor())
            asyncio.create_task(self._metrics_collector())
            asyncio.create_task(self._threat_correlation())
            
            # Start external feed updates
            asyncio.create_task(self._feed_updater())
            
            self.status = ThreatIntelligenceStatus.ACTIVE
            logger.info("Threat Intelligence Engine successfully initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Threat Intelligence Engine: {e}")
            self.status = ThreatIntelligenceStatus.OFFLINE
            return False
    
    async def process_security_event(self, event: Dict[str, Any]) -> Optional[ThreatContext]:
        """Process a security event for threat detection."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Add event to detection queue
            await self.detection_queue.put(event)
            
            # Quick synchronous analysis for immediate threats
            threat_context = await self._analyze_event(event)
            
            if threat_context:
                await self._handle_detected_threat(threat_context)
                
            # Update metrics
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            self.metrics.processing_latency_ms.append(processing_time)
            if len(self.metrics.processing_latency_ms) > 1000:
                self.metrics.processing_latency_ms.pop(0)
                
            return threat_context
            
        except Exception as e:
            logger.error(f"Error processing security event: {e}")
            return None
    
    async def _analyze_event(self, event: Dict[str, Any]) -> Optional[ThreatContext]:
        """Analyze a security event for threat indicators."""
        try:
            # Check against known threat indicators
            indicators = await self.indicator_manager.check_event(event)
            
            if not indicators:
                return None
            
            # Calculate threat confidence and severity
            confidence = self._calculate_threat_confidence(indicators, event)
            severity = self._determine_threat_severity(indicators, confidence)
            
            # Create threat context
            threat_context = ThreatContext(
                threat_type=self._classify_threat_type(indicators, event),
                source=event.get('source', 'unknown'),
                confidence=confidence,
                severity=severity,
                indicators=indicators,
                metadata=self._extract_threat_metadata(event, indicators)
            )
            
            # Check for existing threat context
            existing_threat = self._find_related_threat(threat_context)
            if existing_threat:
                existing_threat.count += 1
                existing_threat.last_seen = datetime.now(timezone.utc)
                existing_threat.indicators.extend(indicators)
                return existing_threat
            
            return threat_context
            
        except Exception as e:
            logger.error(f"Error analyzing security event: {e}")
            return None
    
    async def _handle_detected_threat(self, threat_context: ThreatContext):
        """Handle a detected threat."""
        try:
            # Store active threat
            self.active_threats[threat_context.threat_id] = threat_context
            
            # Add to history
            self.threat_history.append(threat_context)
            
            # Update metrics
            self.metrics.threats_detected += 1
            
            # Trigger threat handlers
            for handler in self.threat_handlers:
                try:
                    await handler(threat_context)
                except Exception as e:
                    logger.error(f"Error in threat handler: {e}")
            
            # Automatic response based on severity
            if threat_context.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                await self.threat_response.execute_immediate_response(threat_context)
                self.metrics.threats_blocked += 1
            
            # Create incident if warranted
            if threat_context.severity == ThreatLevel.CRITICAL or threat_context.count >= 5:
                incident = await self.incident_manager.create_incident(threat_context)
                if incident:
                    self.metrics.incidents_created += 1
                    
                    # Trigger incident handlers
                    for handler in self.incident_handlers:
                        try:
                            await handler(incident)
                        except Exception as e:
                            logger.error(f"Error in incident handler: {e}")
            
            # Collect forensic evidence for high-severity threats
            if threat_context.severity in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                await self.forensics_collector.collect_evidence(threat_context)
            
            logger.info(f"Handled threat: {threat_context.threat_id} "
                       f"({threat_context.threat_type}, severity: {threat_context.severity.value})")
                       
        except Exception as e:
            logger.error(f"Error handling detected threat: {e}")
    
    async def _detection_processor(self):
        """Background processor for detection queue."""
        while True:
            try:
                # Process detection queue
                if not self.detection_queue.empty():
                    event = await asyncio.wait_for(self.detection_queue.get(), timeout=1.0)
                    
                    # Advanced behavioral analysis
                    anomalies = await self.behavioral_analytics.analyze_event(event)
                    if anomalies:
                        for anomaly in anomalies:
                            threat_context = ThreatContext(
                                threat_type="behavioral_anomaly",
                                source=event.get('source', 'behavioral_analytics'),
                                confidence=anomaly.confidence,
                                severity=anomaly.severity,
                                metadata=anomaly.details
                            )
                            await self._handle_detected_threat(threat_context)
                    
                    # Statistical anomaly detection
                    statistical_anomalies = await self.anomaly_detector.detect_anomalies(event)
                    for anomaly in statistical_anomalies:
                        threat_context = ThreatContext(
                            threat_type="statistical_anomaly",
                            source=event.get('source', 'statistical_analysis'),
                            confidence=anomaly.confidence,
                            severity=anomaly.severity,
                            metadata=anomaly.details
                        )
                        await self._handle_detected_threat(threat_context)
                
                await asyncio.sleep(0.1)  # Prevent CPU spinning
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in detection processor: {e}")
                await asyncio.sleep(1)
    
    async def _response_processor(self):
        """Background processor for automated responses."""
        while True:
            try:
                if not self.response_queue.empty():
                    response_task = await asyncio.wait_for(self.response_queue.get(), timeout=1.0)
                    await self.threat_response.execute_response(response_task)
                
                await asyncio.sleep(0.1)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in response processor: {e}")
                await asyncio.sleep(1)
    
    async def _threat_correlation(self):
        """Correlate related threats and detect attack patterns."""
        while True:
            try:
                # Look for patterns in active threats
                patterns = self._detect_attack_patterns()
                
                for pattern in patterns:
                    # Create higher-level threat context for patterns
                    pattern_threat = ThreatContext(
                        threat_type=f"attack_pattern_{pattern['type']}",
                        source="threat_correlation",
                        confidence=pattern['confidence'],
                        severity=pattern['severity'],
                        metadata=pattern['details'],
                        related_incidents=pattern['related_threats']
                    )
                    
                    await self._handle_detected_threat(pattern_threat)
                
                # Clean up old threats
                await self._cleanup_old_threats()
                
                await asyncio.sleep(30)  # Run every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in threat correlation: {e}")
                await asyncio.sleep(60)
    
    async def _feed_updater(self):
        """Update threat intelligence feeds periodically."""
        while True:
            try:
                await self.feed_manager.update_all_feeds()
                self.metrics.feed_updates += 1
                self.metrics.last_feed_update = datetime.now(timezone.utc)
                
                logger.info("Threat intelligence feeds updated")
                
                # Update every 4 hours
                await asyncio.sleep(4 * 3600)
                
            except Exception as e:
                logger.error(f"Error updating threat feeds: {e}")
                await asyncio.sleep(3600)  # Retry in 1 hour
    
    async def _metrics_collector(self):
        """Collect and update engine metrics."""
        while True:
            try:
                # Update component metrics
                await self._update_component_metrics()
                
                # Log periodic status
                if self.metrics.threats_detected > 0:
                    avg_latency = sum(self.metrics.processing_latency_ms) / len(self.metrics.processing_latency_ms)
                    logger.info(f"Threat Intelligence Engine Status: "
                              f"Threats: {self.metrics.threats_detected}, "
                              f"Blocked: {self.metrics.threats_blocked}, "
                              f"Avg Latency: {avg_latency:.2f}ms")
                
                await asyncio.sleep(300)  # Update every 5 minutes
                
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                await asyncio.sleep(300)
    
    def _calculate_threat_confidence(self, indicators: List[ThreatIndicator], event: Dict[str, Any]) -> float:
        """Calculate confidence score for a threat."""
        if not indicators:
            return 0.0
        
        # Base confidence from indicators
        confidence = sum(indicator.confidence for indicator in indicators) / len(indicators)
        
        # Adjust based on event characteristics
        if event.get('source_reliability'):
            confidence *= event['source_reliability']
        
        # Historical accuracy adjustment
        false_positive_rate = self.metrics.false_positives / max(self.metrics.threats_detected, 1)
        confidence *= (1.0 - false_positive_rate * 0.5)
        
        return min(confidence, 1.0)
    
    def _determine_threat_severity(self, indicators: List[ThreatIndicator], confidence: float) -> ThreatLevel:
        """Determine threat severity based on indicators and confidence."""
        if not indicators:
            return ThreatLevel.LOW
        
        # Get maximum severity from indicators
        max_severity = max(indicator.severity for indicator in indicators)
        
        # Adjust based on confidence
        if confidence < 0.3:
            return ThreatLevel.LOW
        elif confidence < 0.6 and max_severity.value >= ThreatLevel.MEDIUM.value:
            return ThreatLevel.MEDIUM
        elif confidence < 0.8 and max_severity.value >= ThreatLevel.HIGH.value:
            return ThreatLevel.HIGH
        else:
            return max_severity
    
    def _classify_threat_type(self, indicators: List[ThreatIndicator], event: Dict[str, Any]) -> str:
        """Classify the type of threat based on indicators and event data."""
        if not indicators:
            return "unknown"
        
        # Get most common threat type from indicators
        threat_types = [indicator.threat_type for indicator in indicators]
        threat_type_counts = defaultdict(int)
        
        for threat_type in threat_types:
            threat_type_counts[threat_type] += 1
        
        return max(threat_type_counts.items(), key=lambda x: x[1])[0]
    
    def _extract_threat_metadata(self, event: Dict[str, Any], indicators: List[ThreatIndicator]) -> Dict[str, Any]:
        """Extract relevant metadata for threat context."""
        metadata = {
            'event_timestamp': event.get('timestamp'),
            'source_ip': event.get('source_ip'),
            'user_agent': event.get('user_agent'),
            'endpoint': event.get('endpoint'),
            'method': event.get('method'),
            'indicator_count': len(indicators),
            'indicator_types': list(set(indicator.ioc_type.value for indicator in indicators)),
            'original_event': event
        }
        
        return metadata
    
    def _find_related_threat(self, threat_context: ThreatContext) -> Optional[ThreatContext]:
        """Find related active threat based on similarity."""
        for active_threat in self.active_threats.values():
            # Check if threats are similar
            if (active_threat.threat_type == threat_context.threat_type and
                active_threat.source == threat_context.source and
                abs((active_threat.first_seen - threat_context.first_seen).total_seconds()) < 300):
                return active_threat
        
        return None
    
    def _detect_attack_patterns(self) -> List[Dict[str, Any]]:
        """Detect attack patterns from active threats."""
        patterns = []
        
        # Group threats by source IP
        threats_by_ip = defaultdict(list)
        for threat in self.active_threats.values():
            source_ip = threat.metadata.get('source_ip')
            if source_ip:
                threats_by_ip[source_ip].append(threat)
        
        # Detect brute force patterns
        for ip, threats in threats_by_ip.items():
            if len(threats) >= 5:
                pattern = {
                    'type': 'brute_force',
                    'confidence': min(0.9, len(threats) / 10),
                    'severity': ThreatLevel.HIGH,
                    'details': {
                        'source_ip': ip,
                        'threat_count': len(threats),
                        'time_window': '5_minutes'
                    },
                    'related_threats': [t.threat_id for t in threats]
                }
                patterns.append(pattern)
        
        return patterns
    
    async def _cleanup_old_threats(self):
        """Clean up old threat contexts."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
        
        threats_to_remove = []
        for threat_id, threat in self.active_threats.items():
            if threat.last_seen < cutoff_time:
                threats_to_remove.append(threat_id)
        
        for threat_id in threats_to_remove:
            del self.active_threats[threat_id]
    
    async def _update_component_metrics(self):
        """Update metrics from all components."""
        # This would collect metrics from all components
        pass
    
    def register_threat_handler(self, handler: Callable):
        """Register a threat event handler."""
        self.threat_handlers.append(handler)
    
    def register_incident_handler(self, handler: Callable):
        """Register an incident event handler."""
        self.incident_handlers.append(handler)
    
    async def get_active_threats(self) -> List[ThreatContext]:
        """Get all currently active threats."""
        return list(self.active_threats.values())
    
    async def get_threat_summary(self) -> Dict[str, Any]:
        """Get a summary of threat intelligence status."""
        return {
            'status': self.status.value,
            'metrics': {
                'threats_detected': self.metrics.threats_detected,
                'threats_blocked': self.metrics.threats_blocked,
                'false_positives': self.metrics.false_positives,
                'incidents_created': self.metrics.incidents_created,
                'active_threats': len(self.active_threats),
                'uptime_hours': (datetime.now(timezone.utc) - self.metrics.uptime_start).total_seconds() / 3600,
                'avg_processing_latency_ms': sum(self.metrics.processing_latency_ms) / max(len(self.metrics.processing_latency_ms), 1)
            },
            'active_threats': [
                {
                    'id': threat.threat_id,
                    'type': threat.threat_type,
                    'severity': threat.severity.value,
                    'confidence': threat.confidence,
                    'count': threat.count,
                    'first_seen': threat.first_seen.isoformat(),
                    'last_seen': threat.last_seen.isoformat()
                }
                for threat in self.active_threats.values()
            ]
        }
    
    async def shutdown(self):
        """Shutdown the threat intelligence engine."""
        logger.info("Shutting down Threat Intelligence Engine")
        self.status = ThreatIntelligenceStatus.OFFLINE
        
        # Shutdown all components
        await self.indicator_manager.shutdown()
        await self.behavioral_analytics.shutdown()
        await self.anomaly_detector.shutdown()
        await self.security_monitor.shutdown()
        await self.event_processor.shutdown()
        await self.threat_response.shutdown()
        await self.incident_manager.shutdown()
        await self.feed_manager.shutdown()
        await self.forensics_collector.shutdown()
        
        logger.info("Threat Intelligence Engine shutdown complete")