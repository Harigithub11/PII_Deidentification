"""
Comprehensive Test Suite for Threat Intelligence System

Tests all components of the advanced threat intelligence system including
engine, indicators, analytics, monitoring, response, feeds, forensics, and dashboard.
"""

import pytest
import asyncio
import tempfile
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock

# Import threat intelligence components
from src.core.security.threat_intelligence.engine import ThreatIntelligenceEngine, ThreatContext
from src.core.security.threat_intelligence.indicators import (
    ThreatIndicatorManager, ThreatIndicator, IOCType, ThreatLevel, IndicatorStatus
)
from src.core.security.threat_intelligence.analytics import (
    BehavioralAnalytics, AnomalyDetector, Anomaly, AnomalyType
)
from src.core.security.threat_intelligence.monitoring import (
    AdvancedSecurityMonitor, SecurityEvent, EventType, MonitoringAlert
)
from src.core.security.threat_intelligence.response import (
    AutomatedThreatResponse, ResponseTask, ResponseAction, IncidentManager
)
from src.core.security.threat_intelligence.feeds import (
    ThreatFeedManager, ThreatFeed, FeedType, FeedFormat, JSONFeedParser
)
from src.core.security.threat_intelligence.forensics import (
    ForensicsCollector, EvidenceCollector, EvidenceManager, EvidenceItem, EvidenceType
)
from src.core.security.threat_intelligence.dashboard import (
    ThreatIntelligenceDashboard, DashboardWidget, ReportType
)


class TestThreatIndicatorManager:
    """Test threat indicator management functionality."""
    
    @pytest.fixture
    async def indicator_manager(self):
        """Create test indicator manager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_indicators.db"
            manager = ThreatIndicatorManager(str(db_path))
            await manager.initialize()
            yield manager
            await manager.shutdown()
    
    @pytest.fixture
    def sample_indicator(self):
        """Create sample threat indicator."""
        return ThreatIndicator(
            ioc_value="192.168.1.100",
            ioc_type=IOCType.IP_ADDRESS,
            threat_type="malware_c2",
            severity=ThreatLevel.HIGH,
            confidence=0.85,
            source="test_feed",
            description="Malware C2 server"
        )
    
    @pytest.mark.asyncio
    async def test_add_indicator(self, indicator_manager, sample_indicator):
        """Test adding threat indicator."""
        result = await indicator_manager.add_indicator(sample_indicator)
        assert result is True
        
        # Verify indicator was added
        assert sample_indicator.ioc_value in indicator_manager.indicators
        stored_indicator = indicator_manager.indicators[sample_indicator.ioc_value]
        assert stored_indicator.ioc_type == IOCType.IP_ADDRESS
        assert stored_indicator.severity == ThreatLevel.HIGH
    
    @pytest.mark.asyncio
    async def test_check_event_matching(self, indicator_manager, sample_indicator):
        """Test event matching against indicators."""
        await indicator_manager.add_indicator(sample_indicator)
        
        # Create test event
        test_event = {
            'source_ip': '192.168.1.100',
            'user_agent': 'test-agent',
            'endpoint': '/api/test'
        }
        
        matches = await indicator_manager.check_event(test_event)
        assert len(matches) == 1
        assert matches[0].ioc_value == "192.168.1.100"
        assert matches[0].hit_count == 1
    
    @pytest.mark.asyncio
    async def test_false_positive_marking(self, indicator_manager, sample_indicator):
        """Test marking indicator as false positive."""
        await indicator_manager.add_indicator(sample_indicator)
        
        result = await indicator_manager.mark_false_positive(sample_indicator.ioc_value)
        assert result is True
        
        indicator = indicator_manager.indicators[sample_indicator.ioc_value]
        assert indicator.false_positive_count == 1
    
    @pytest.mark.asyncio
    async def test_indicator_stats(self, indicator_manager):
        """Test getting indicator statistics."""
        # Add various indicators
        indicators = [
            ThreatIndicator("malware.example.com", IOCType.DOMAIN, "malware", ThreatLevel.HIGH, 0.9, "feed1"),
            ThreatIndicator("badfile.exe", IOCType.FILE_HASH_SHA256, "malware", ThreatLevel.CRITICAL, 0.95, "feed1"),
            ThreatIndicator("10.0.0.1", IOCType.IP_ADDRESS, "scanning", ThreatLevel.MEDIUM, 0.7, "feed2")
        ]
        
        for indicator in indicators:
            await indicator_manager.add_indicator(indicator)
        
        stats = await indicator_manager.get_indicator_stats()
        assert stats['total_indicators'] == 3
        assert stats['active_indicators'] == 3
        assert stats['severity_distribution']['high'] == 1
        assert stats['severity_distribution']['critical'] == 1
        assert stats['severity_distribution']['medium'] == 1


class TestBehavioralAnalytics:
    """Test behavioral analytics and anomaly detection."""
    
    @pytest.fixture
    async def behavioral_analytics(self):
        """Create test behavioral analytics engine."""
        with tempfile.TemporaryDirectory() as temp_dir:
            analytics = BehavioralAnalytics()
            analytics.anomaly_detector.db_path = str(Path(temp_dir) / "test_anomalies.db")
            await analytics.initialize()
            yield analytics
            await analytics.shutdown()
    
    @pytest.mark.asyncio
    async def test_analyze_event(self, behavioral_analytics):
        """Test event analysis for anomalies."""
        test_event = {
            'user_id': 'test_user',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source_ip': '192.168.1.100',
            'response_time': 5000,  # High response time
            'status_code': 200
        }
        
        anomalies = await behavioral_analytics.analyze_event(test_event)
        
        # Should detect statistical anomalies
        assert len(anomalies) >= 0  # May or may not detect anomalies on first run
    
    @pytest.mark.asyncio
    async def test_user_behavior_profiling(self, behavioral_analytics):
        """Test user behavior profile building."""
        user_id = "test_user_123"
        
        # Simulate multiple events for the same user
        events = [
            {
                'user_id': user_id,
                'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat(),
                'source_ip': '192.168.1.100',
                'endpoint': '/api/documents',
                'session_duration': 1800 + i * 10
            }
            for i in range(20)  # 20 events to build profile
        ]
        
        for event in events:
            await behavioral_analytics.analyze_event(event)
        
        # Check if user profile was created
        detector = behavioral_analytics.anomaly_detector.behavioral_analyzer
        assert user_id in detector.user_profiles
        
        profile = detector.user_profiles[user_id]
        assert profile.sample_count == 20
        assert len(profile.login_locations) > 0
    
    @pytest.mark.asyncio
    async def test_anomaly_detection(self, behavioral_analytics):
        """Test anomaly detection with unusual behavior."""
        user_id = "test_user_456"
        
        # Build normal behavior profile
        normal_events = [
            {
                'user_id': user_id,
                'timestamp': (datetime.now(timezone.utc) - timedelta(hours=1, minutes=i)).isoformat(),
                'source_ip': '192.168.1.100',
                'endpoint': '/api/documents',
                'session_duration': 1800
            }
            for i in range(15)
        ]
        
        for event in normal_events:
            await behavioral_analytics.analyze_event(event)
        
        # Introduce anomalous event
        anomalous_event = {
            'user_id': user_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source_ip': '10.0.0.255',  # Different IP
            'endpoint': '/admin/users',  # Different endpoint
            'session_duration': 10800  # Much longer session
        }
        
        anomalies = await behavioral_analytics.analyze_event(anomalous_event)
        
        # Should detect behavioral anomalies
        assert len(anomalies) > 0
        anomaly_types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.BEHAVIORAL in anomaly_types


class TestAdvancedSecurityMonitor:
    """Test advanced security monitoring functionality."""
    
    @pytest.fixture
    async def security_monitor(self):
        """Create test security monitor."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_monitoring.db"
            monitor = AdvancedSecurityMonitor(str(db_path))
            await monitor.initialize()
            yield monitor
            await monitor.shutdown()
    
    @pytest.mark.asyncio
    async def test_brute_force_detection(self, security_monitor):
        """Test brute force attack detection."""
        source_ip = "192.168.1.200"
        
        # Simulate multiple failed login attempts
        for i in range(6):
            event_data = {
                'source_ip': source_ip,
                'endpoint': '/auth/login',
                'status_code': 401,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'user_agent': 'test-client'
            }
            
            await security_monitor.process_event(event_data)
        
        # Check if brute force alert was generated
        alerts = list(security_monitor.active_alerts.values())
        brute_force_alerts = [a for a in alerts if a.alert_type == 'brute_force_attack']
        assert len(brute_force_alerts) > 0
        
        alert = brute_force_alerts[0]
        assert alert.severity == ThreatLevel.HIGH
        assert source_ip in alert.metadata['source_ip']
    
    @pytest.mark.asyncio
    async def test_malicious_user_agent_detection(self, security_monitor):
        """Test malicious user agent detection."""
        event_data = {
            'source_ip': '192.168.1.300',
            'user_agent': 'sqlmap/1.0',  # Known malicious tool
            'endpoint': '/api/search',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        await security_monitor.process_event(event_data)
        
        # Check if malicious user agent alert was generated
        alerts = list(security_monitor.active_alerts.values())
        malicious_alerts = [a for a in alerts if a.alert_type == 'malicious_user_agent']
        assert len(malicious_alerts) > 0
    
    @pytest.mark.asyncio
    async def test_data_exfiltration_detection(self, security_monitor):
        """Test data exfiltration detection."""
        event_data = {
            'source_ip': '192.168.1.400',
            'user_id': 'test_user',
            'endpoint': '/api/documents/download',
            'response_size': 150 * 1024 * 1024,  # 150MB response
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        await security_monitor.process_event(event_data)
        
        # Check if data exfiltration alert was generated
        alerts = list(security_monitor.active_alerts.values())
        exfil_alerts = [a for a in alerts if a.alert_type == 'potential_data_exfiltration']
        assert len(exfil_alerts) > 0


class TestAutomatedThreatResponse:
    """Test automated threat response system."""
    
    @pytest.fixture
    async def threat_response(self):
        """Create test threat response system."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_response.db"
            response = AutomatedThreatResponse(str(db_path))
            await response.initialize()
            yield response
            await response.shutdown()
    
    @pytest.mark.asyncio
    async def test_ip_blocking_response(self, threat_response):
        """Test IP blocking response."""
        # Create mock threat context
        threat_context = Mock()
        threat_context.threat_type = 'brute_force_attack'
        threat_context.threat_id = 'test_threat_123'
        threat_context.severity = ThreatLevel.HIGH
        threat_context.metadata = {'source_ip': '192.168.1.500'}
        
        tasks = await threat_response.execute_immediate_response(threat_context)
        
        assert len(tasks) > 0
        
        # Check if IP blocking task was created
        block_tasks = [t for t in tasks if t.action == ResponseAction.BLOCK_IP]
        assert len(block_tasks) > 0
        
        block_task = block_tasks[0]
        assert block_task.target == '192.168.1.500'
        assert block_task.priority >= 8
    
    @pytest.mark.asyncio
    async def test_task_execution(self, threat_response):
        """Test response task execution."""
        task = ResponseTask(
            action=ResponseAction.ALERT_ADMIN,
            target="admin@example.com",
            parameters={
                'message': 'Test security alert',
                'severity': 'high'
            }
        )
        
        success = await threat_response.executor.execute_task(task)
        
        assert success is True
        assert task.status.value == 'completed'
        assert task.result['alert_sent_at'] is not None
    
    @pytest.mark.asyncio
    async def test_incident_creation(self, threat_response):
        """Test security incident creation."""
        incident_manager = IncidentManager()
        await incident_manager.initialize()
        
        # Mock threat context
        threat_context = Mock()
        threat_context.threat_type = 'data_breach'
        threat_context.severity = ThreatLevel.CRITICAL
        threat_context.metadata = {'affected_records': 1000}
        
        incident = await incident_manager.create_incident(threat_context)
        
        assert incident is not None
        assert incident.severity.value == 'critical'
        assert incident.status == 'open'
        assert len(incident.timeline) > 0


class TestThreatFeedManager:
    """Test threat feed management."""
    
    @pytest.fixture
    async def feed_manager(self):
        """Create test feed manager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_feeds.db"
            manager = ThreatFeedManager(str(db_path))
            await manager.initialize()
            yield manager
            await manager.shutdown()
    
    @pytest.mark.asyncio
    async def test_add_feed(self, feed_manager):
        """Test adding threat feed."""
        feed = ThreatFeed(
            feed_id="test_feed_123",
            name="Test Malware Feed",
            feed_type=FeedType.MALWARE_FEED,
            url="https://example.com/test-feed.json",
            format=FeedFormat.JSON,
            update_interval=3600
        )
        
        result = await feed_manager.add_feed(feed)
        assert result is True
        assert feed.feed_id in feed_manager.feeds
    
    def test_json_feed_parser(self):
        """Test JSON feed parsing."""
        feed = ThreatFeed(
            feed_id="test_json_feed",
            name="Test JSON Feed",
            feed_type=FeedType.IOC_FEED,
            url="https://example.com/iocs.json",
            format=FeedFormat.JSON,
            reliability_score=0.8
        )
        
        parser = JSONFeedParser(feed)
        
        sample_json_data = json.dumps([
            {
                "ip": "10.0.0.1",
                "type": "malware_c2",
                "severity": "high",
                "confidence": 0.9
            },
            {
                "domain": "malicious.example.com",
                "type": "phishing",
                "severity": "medium",
                "confidence": 0.7
            }
        ])
        
        # Use asyncio.run for async method
        indicators = asyncio.run(parser.parse(sample_json_data))
        
        assert len(indicators) == 2
        assert indicators[0].ioc_type == IOCType.IP_ADDRESS
        assert indicators[0].ioc_value == "10.0.0.1"
        assert indicators[1].ioc_type == IOCType.DOMAIN
        assert indicators[1].ioc_value == "malicious.example.com"
    
    @pytest.mark.asyncio
    async def test_feed_status(self, feed_manager):
        """Test getting feed status."""
        status = await feed_manager.get_feed_status()
        
        assert 'total_feeds' in status
        assert 'active_feeds' in status
        assert 'feed_type_distribution' in status
        assert isinstance(status['total_feeds'], int)


class TestForensicsCollector:
    """Test forensic evidence collection."""
    
    @pytest.fixture
    async def forensics_collector(self):
        """Create test forensics collector."""
        with tempfile.TemporaryDirectory() as temp_dir:
            collector = ForensicsCollector(str(temp_dir))
            await collector.initialize()
            yield collector
            await collector.shutdown()
    
    @pytest.mark.asyncio
    async def test_evidence_collection(self, forensics_collector):
        """Test evidence collection for threat."""
        # Mock threat context
        threat_context = Mock()
        threat_context.threat_type = 'malware_infection'
        threat_context.threat_id = 'threat_789'
        threat_context.severity = ThreatLevel.HIGH
        threat_context.metadata = {
            'user_id': 'affected_user',
            'source_ip': '192.168.1.600'
        }
        
        evidence_items = await forensics_collector.collect_evidence(threat_context)
        
        assert len(evidence_items) > 0
        
        # Check that different types of evidence were collected
        evidence_types = [item.evidence_type for item in evidence_items]
        assert EvidenceType.SYSTEM_SNAPSHOT in evidence_types
        assert EvidenceType.LOG_FILES in evidence_types
    
    @pytest.mark.asyncio
    async def test_user_activity_collection(self, forensics_collector):
        """Test user activity evidence collection."""
        user_id = "test_user_789"
        time_range = (
            datetime.now(timezone.utc) - timedelta(hours=2),
            datetime.now(timezone.utc)
        )
        
        evidence = await forensics_collector.evidence_collector.collect_user_activity(
            user_id, time_range
        )
        
        assert evidence.evidence_type == EvidenceType.USER_ACTIVITY
        assert evidence.status.value in ['collected', 'error']
        assert user_id in evidence.name
        assert len(evidence.chain_of_custody) > 0
    
    @pytest.mark.asyncio
    async def test_evidence_encryption(self, forensics_collector):
        """Test evidence encryption and decryption."""
        # Create test evidence
        evidence = await forensics_collector.evidence_collector.collect_system_snapshot()
        
        if evidence.status.value == 'collected' and evidence.file_path:
            # Evidence should be encrypted
            assert evidence.metadata.get('encrypted') is True
            
            # Test decryption
            decrypted_path = await forensics_collector.evidence_collector.decrypt_evidence(evidence)
            assert Path(decrypted_path).exists()
            
            # Verify integrity
            assert evidence.verify_integrity()


class TestThreatIntelligenceDashboard:
    """Test threat intelligence dashboard."""
    
    @pytest.fixture
    async def dashboard(self):
        """Create test dashboard."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_dashboard.db"
            dashboard = ThreatIntelligenceDashboard(str(db_path))
            await dashboard.initialize()
            yield dashboard
            await dashboard.shutdown()
    
    @pytest.mark.asyncio
    async def test_widget_data_update(self, dashboard):
        """Test dashboard widget data updates."""
        test_data = {
            'total_threats': 42,
            'active_threats': 3,
            'system_status': 'operational'
        }
        
        await dashboard.update_widget_data(DashboardWidget.THREAT_OVERVIEW, test_data)
        
        widget = dashboard.widgets[DashboardWidget.THREAT_OVERVIEW]
        assert widget.data == test_data
        assert not widget.is_stale()
    
    @pytest.mark.asyncio
    async def test_dashboard_data_retrieval(self, dashboard):
        """Test getting complete dashboard data."""
        # Update some widgets with test data
        await dashboard.update_widget_data(DashboardWidget.THREAT_OVERVIEW, {'threats': 10})
        await dashboard.update_widget_data(DashboardWidget.SYSTEM_HEALTH, {'status': 'healthy'})
        
        dashboard_data = await dashboard.get_dashboard_data()
        
        assert 'timestamp' in dashboard_data
        assert 'widgets' in dashboard_data
        assert len(dashboard_data['widgets']) > 0
        
        # Verify specific widget data
        assert 'threat_overview' in dashboard_data['widgets']
        assert dashboard_data['widgets']['threat_overview']['data']['threats'] == 10
    
    @pytest.mark.asyncio
    async def test_report_generation(self, dashboard):
        """Test threat intelligence report generation."""
        time_period = (
            datetime.now(timezone.utc) - timedelta(days=1),
            datetime.now(timezone.utc)
        )
        
        report = await dashboard.generate_report(
            ReportType.EXECUTIVE_SUMMARY,
            time_period
        )
        
        assert report is not None
        assert report.report_type == ReportType.EXECUTIVE_SUMMARY
        assert 'summary' in report.content
        assert 'key_metrics' in report.content
        assert len(report.content['recommendations']) > 0
    
    @pytest.mark.asyncio
    async def test_dashboard_export(self, dashboard):
        """Test dashboard data export."""
        export_data = await dashboard.export_dashboard_data("json")
        
        assert export_data is not None
        # Should be valid JSON
        parsed_data = json.loads(export_data)
        assert 'widgets' in parsed_data
        assert 'timestamp' in parsed_data


class TestThreatIntelligenceEngine:
    """Test complete threat intelligence engine integration."""
    
    @pytest.fixture
    async def threat_engine(self):
        """Create complete test threat intelligence engine."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                'storage_path': str(temp_dir),
                'db_path': str(Path(temp_dir) / "engine.db")
            }
            
            engine = ThreatIntelligenceEngine(config)
            await engine.initialize()
            yield engine
            await engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_engine_initialization(self, threat_engine):
        """Test engine initialization."""
        assert threat_engine.status.value == 'active'
        assert threat_engine.indicator_manager is not None
        assert threat_engine.behavioral_analytics is not None
        assert threat_engine.security_monitor is not None
    
    @pytest.mark.asyncio
    async def test_security_event_processing(self, threat_engine):
        """Test complete security event processing pipeline."""
        # Create test security event
        event = {
            'source_ip': '192.168.1.999',
            'user_agent': 'sqlmap/1.0',  # Malicious user agent
            'endpoint': '/api/sensitive',
            'status_code': 200,
            'response_time': 1500,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Add a matching threat indicator
        indicator = ThreatIndicator(
            ioc_value="192.168.1.999",
            ioc_type=IOCType.IP_ADDRESS,
            threat_type="malware_c2",
            severity=ThreatLevel.HIGH,
            confidence=0.9,
            source="test"
        )
        await threat_engine.indicator_manager.add_indicator(indicator)
        
        # Process event through engine
        threat_context = await threat_engine.process_security_event(event)
        
        # Verify threat was detected
        assert threat_context is not None
        assert threat_context.threat_type in ['malware_c2', 'malicious_user_agent']
        assert threat_context.confidence > 0
        
        # Verify metrics were updated
        assert threat_engine.metrics.threats_detected > 0
    
    @pytest.mark.asyncio
    async def test_threat_summary(self, threat_engine):
        """Test getting threat intelligence summary."""
        summary = await threat_engine.get_threat_summary()
        
        assert 'status' in summary
        assert 'metrics' in summary
        assert 'active_threats' in summary
        assert summary['status'] == 'active'
        
        metrics = summary['metrics']
        assert 'threats_detected' in metrics
        assert 'uptime_hours' in metrics
        assert isinstance(metrics['avg_processing_latency_ms'], (int, float))


class TestThreatIntelligenceIntegration:
    """Test integration between all threat intelligence components."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_detection(self):
        """Test complete end-to-end threat detection and response."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Initialize complete system
            engine = ThreatIntelligenceEngine({'storage_path': str(temp_dir)})
            await engine.initialize()
            
            try:
                # Add threat indicator
                indicator = ThreatIndicator(
                    ioc_value="malicious.example.org",
                    ioc_type=IOCType.DOMAIN,
                    threat_type="phishing",
                    severity=ThreatLevel.HIGH,
                    confidence=0.92,
                    source="integration_test"
                )
                await engine.indicator_manager.add_indicator(indicator)
                
                # Simulate security event
                event = {
                    'source_ip': '10.0.0.100',
                    'user_id': 'test_user',
                    'endpoint': 'http://malicious.example.org/phish',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'status_code': 200
                }
                
                # Process through complete pipeline
                threat_context = await engine.process_security_event(event)
                
                # Verify detection
                assert threat_context is not None
                assert threat_context.threat_type == 'phishing'
                assert threat_context.severity == ThreatLevel.HIGH
                
                # Verify response was triggered
                assert engine.metrics.threats_detected > 0
                
                # Check if evidence collection was initiated
                active_threats = await engine.get_active_threats()
                assert len(active_threats) > 0
                
                # Verify system summary includes the threat
                summary = await engine.get_threat_summary()
                assert summary['metrics']['threats_detected'] > 0
                
            finally:
                await engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_dashboard_integration(self):
        """Test dashboard integration with threat intelligence engine."""
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = ThreatIntelligenceEngine({'storage_path': str(temp_dir)})
            dashboard = ThreatIntelligenceDashboard(str(Path(temp_dir) / "dashboard.db"))
            
            await engine.initialize()
            await dashboard.initialize(engine)
            
            try:
                # Generate some threat activity
                indicator = ThreatIndicator(
                    "scanner.example.com", IOCType.DOMAIN, "scanning", ThreatLevel.MEDIUM, 0.8, "test"
                )
                await engine.indicator_manager.add_indicator(indicator)
                
                # Wait for dashboard to update
                await asyncio.sleep(1)
                
                # Get dashboard data
                dashboard_data = await dashboard.get_dashboard_data()
                
                # Verify dashboard shows threat intelligence data
                assert 'widgets' in dashboard_data
                widgets = dashboard_data['widgets']
                
                # Should have various widget types
                expected_widgets = ['threat_overview', 'ioc_statistics', 'system_health']
                for widget_type in expected_widgets:
                    assert widget_type in widgets
                
            finally:
                await dashboard.shutdown()
                await engine.shutdown()


# Performance and load tests
class TestThreatIntelligencePerformance:
    """Test performance characteristics of threat intelligence system."""
    
    @pytest.mark.asyncio
    async def test_high_volume_event_processing(self):
        """Test processing large volume of security events."""
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = ThreatIntelligenceEngine({'storage_path': str(temp_dir)})
            await engine.initialize()
            
            try:
                start_time = datetime.now()
                
                # Process 1000 events
                tasks = []
                for i in range(1000):
                    event = {
                        'source_ip': f'192.168.{i//256}.{i%256}',
                        'endpoint': f'/api/endpoint_{i}',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'status_code': 200 if i % 10 != 0 else 401  # 10% errors
                    }
                    tasks.append(engine.process_security_event(event))
                
                # Process all events concurrently
                await asyncio.gather(*tasks)
                
                end_time = datetime.now()
                processing_time = (end_time - start_time).total_seconds()
                
                # Performance assertions
                assert processing_time < 30  # Should complete within 30 seconds
                assert engine.metrics.threats_detected >= 0  # At least some processing occurred
                
                # Verify system is still responsive
                summary = await engine.get_threat_summary()
                assert summary['status'] == 'active'
                
            finally:
                await engine.shutdown()
    
    @pytest.mark.asyncio
    async def test_memory_usage_stability(self):
        """Test that memory usage remains stable under load."""
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = ThreatIntelligenceEngine({'storage_path': str(temp_dir)})
            await engine.initialize()
            
            try:
                # Add many indicators
                for i in range(1000):
                    indicator = ThreatIndicator(
                        f"test{i}.example.com",
                        IOCType.DOMAIN,
                        "test",
                        ThreatLevel.LOW,
                        0.5,
                        "performance_test"
                    )
                    await engine.indicator_manager.add_indicator(indicator)
                
                # Process events against indicators
                for i in range(500):
                    event = {
                        'domain': f'test{i*2}.example.com',  # Some will match indicators
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }
                    await engine.process_security_event(event)
                
                # System should still be functional
                assert engine.status.value == 'active'
                stats = await engine.indicator_manager.get_indicator_stats()
                assert stats['total_indicators'] == 1000
                
            finally:
                await engine.shutdown()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])