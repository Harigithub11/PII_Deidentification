"""
API Endpoints Test Suite

This module contains comprehensive tests for PCI DSS API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
import json

from src.api.pci_dss_endpoints import pci_dss_router, include_pci_dss_routes
from src.core.compliance.pci_dss_core import PCIDSSComplianceEngine
from src.core.compliance.card_data_protection import CardDataProtectionManager, CardDataType
from src.core.compliance.network_security import NetworkSecurityManager
from src.core.compliance.access_control import AccessControlManager, UserRole
from src.core.compliance.monitoring_system import SecurityMonitoringSystem, EventType


@pytest.fixture
def app():
    """Create test FastAPI application."""
    app = FastAPI()
    include_pci_dss_routes(app)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def mock_compliance_engine():
    """Mock compliance engine."""
    engine = Mock(spec=PCIDSSComplianceEngine)
    
    # Mock comprehensive assessment
    engine.run_comprehensive_assessment = AsyncMock(return_value={
        'assessment_id': 'test_assessment_123',
        'overall_status': 'compliant',
        'compliance_score': 0.95,
        'requirements': [
            {'requirement': '1', 'status': 'compliant', 'score': 1.0},
            {'requirement': '2', 'status': 'compliant', 'score': 0.9}
        ],
        'recommendations': ['Maintain current security posture'],
        'assessment_date': datetime.utcnow().isoformat()
    })
    
    # Mock compliance status
    engine.get_compliance_status = AsyncMock(return_value={
        'overall_status': 'compliant',
        'compliance_score': 0.95,
        'last_assessment': datetime.utcnow().isoformat()
    })
    
    # Mock assessment history
    engine.get_assessment_history = AsyncMock(return_value=[
        {
            'assessment_id': 'test_123',
            'date': datetime.utcnow().isoformat(),
            'status': 'compliant',
            'score': 0.95
        }
    ])
    
    return engine


@pytest.fixture
def mock_card_protection_manager():
    """Mock card data protection manager."""
    manager = Mock(spec=CardDataProtectionManager)
    
    # Mock card data detection
    manager.detect_card_data = AsyncMock(return_value=[
        {
            'type': CardDataType.PRIMARY_ACCOUNT_NUMBER,
            'value': '4111111111111111',
            'confidence': 0.95,
            'position': (0, 16)
        }
    ])
    
    # Mock encryption
    from src.core.compliance.card_data_protection import CardDataElement
    encrypted_element = CardDataElement(
        data_type=CardDataType.PRIMARY_ACCOUNT_NUMBER,
        value="encrypted_value_here",
        encrypted=True,
        encryption_key_id="key_123"
    )
    manager.encrypt_card_data = AsyncMock(return_value=encrypted_element)
    
    # Mock compliance status
    manager.get_compliance_status = AsyncMock(return_value={
        'requirement_3': {'status': 'compliant'},
        'requirement_4': {'status': 'compliant'},
        'overall_compliance': 'compliant'
    })
    
    return manager


@pytest.fixture
def mock_network_security_manager():
    """Mock network security manager."""
    manager = Mock(spec=NetworkSecurityManager)
    
    # Mock vulnerability scan
    manager.perform_vulnerability_scan = AsyncMock(return_value={
        'scan_id': 'scan_123',
        'scan_date': datetime.utcnow().isoformat(),
        'targets': ['192.168.1.100', '192.168.1.101'],
        'vulnerabilities': [],
        'summary': {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'informational': 5
        }
    })
    
    # Mock topology discovery
    manager.discover_network_topology = AsyncMock(return_value={
        'interfaces': {'eth0': {'ip': '192.168.1.50'}},
        'devices': {'device1': {'ip': '192.168.1.100'}},
        'subnets': {'192.168.1.0/24': {'hosts': 254}},
        'zones': {'internal': {'networks': ['192.168.1.0/24']}}
    })
    
    # Mock firewall configuration
    manager.configure_firewall_rules = AsyncMock(return_value={
        'configured_rules': 5,
        'failed_rules': 0,
        'errors': []
    })
    
    # Mock compliance status
    manager.get_compliance_status = AsyncMock(return_value={
        'requirement_1': {'status': 'compliant'},
        'requirement_2': {'status': 'compliant'},
        'requirement_11': {'status': 'compliant'},
        'overall_compliance': 'compliant'
    })
    
    return manager


@pytest.fixture
def mock_access_control_manager():
    """Mock access control manager."""
    manager = Mock(spec=AccessControlManager)
    
    # Mock user creation
    from src.core.compliance.access_control import User, AccountStatus
    test_user = User(
        user_id='user_123',
        username='testuser',
        email='test@example.com',
        full_name='Test User',
        role=UserRole.DATA_PROCESSOR,
        status=AccountStatus.ACTIVE,
        created_at=datetime.utcnow()
    )
    manager.create_user = AsyncMock(return_value=test_user)
    
    # Mock authentication
    from src.core.compliance.access_control import Session
    test_session = Session(
        session_id='session_123',
        user_id='user_123',
        ip_address='192.168.1.100',
        user_agent='Test Agent',
        created_at=datetime.utcnow(),
        last_activity=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=2)
    )
    manager.authenticate_user = AsyncMock(return_value=test_session)
    
    # Mock compliance status
    manager.get_compliance_status = AsyncMock(return_value={
        'requirement_7': {'status': 'compliant'},
        'requirement_8': {'status': 'compliant'},
        'overall_compliance': 'compliant'
    })
    
    # Mock user activity report
    manager.get_user_activity_report = AsyncMock(return_value={
        'user_id': 'user_123',
        'username': 'testuser',
        'total_access_events': 50,
        'successful_events': 48,
        'failed_events': 2,
        'high_risk_events': 0
    })
    
    return manager


@pytest.fixture
def mock_monitoring_system():
    """Mock security monitoring system."""
    system = Mock(spec=SecurityMonitoringSystem)
    
    # Mock event logging
    from src.core.compliance.monitoring_system import SecurityEvent, Severity
    test_event = SecurityEvent(
        event_id='event_123',
        event_type=EventType.LOGIN_SUCCESS,
        timestamp=datetime.utcnow(),
        user_id='user_123',
        source_ip='192.168.1.100',
        user_agent='Test Agent',
        resource='test_resource',
        action='login',
        outcome='success',
        severity=Severity.LOW,
        description='Test event'
    )
    system.log_security_event = AsyncMock(return_value=test_event)
    
    # Mock dashboard
    system.get_security_dashboard = AsyncMock(return_value={
        'timestamp': datetime.utcnow().isoformat(),
        'summary': {
            'total_events_24h': 100,
            'active_alerts': 2,
            'critical_alerts': 0,
            'high_risk_events': 1
        },
        'event_statistics': {
            'login_success': 50,
            'login_failure': 5,
            'pii_access': 20
        },
        'active_alerts': [
            {
                'alert_id': 'alert_123',
                'title': 'Test Alert',
                'severity': 'medium',
                'created_at': datetime.utcnow().isoformat(),
                'event_count': 3
            }
        ],
        'recent_high_risk_events': [],
        'system_metrics': {
            'latest_metrics': {
                'cpu_usage_percent': 25.0,
                'memory_usage_percent': 60.0
            }
        }
    })
    
    # Mock alert operations
    system.security_alerts = {
        'alert_123': Mock(
            alert_id='alert_123',
            status='active',
            severity='medium',
            created_at=datetime.utcnow()
        )
    }
    system.acknowledge_alert = AsyncMock(return_value=True)
    system.resolve_alert = AsyncMock(return_value=True)
    
    # Mock compliance status
    system.get_compliance_status = AsyncMock(return_value={
        'requirement_10': {'status': 'compliant'},
        'requirement_12': {'status': 'compliant'},
        'overall_compliance': 'compliant'
    })
    
    # Mock audit report
    system.generate_audit_report = AsyncMock(return_value={
        'report_period': {
            'start_date': (datetime.utcnow() - timedelta(days=7)).isoformat(),
            'end_date': datetime.utcnow().isoformat()
        },
        'summary': {
            'total_events': 500,
            'unique_users': 10,
            'high_risk_events': 2
        },
        'event_breakdown': {
            'login_success': 250,
            'pii_access': 100,
            'login_failure': 25
        }
    })
    
    return system


# Mock dependency overrides for testing
@pytest.fixture(autouse=True)
def mock_dependencies(
    mock_compliance_engine,
    mock_card_protection_manager,
    mock_network_security_manager,
    mock_access_control_manager,
    mock_monitoring_system
):
    """Override API dependencies with mocks."""
    with patch('src.api.pci_dss_endpoints.get_compliance_engine', return_value=mock_compliance_engine), \
         patch('src.api.pci_dss_endpoints.get_card_protection_manager', return_value=mock_card_protection_manager), \
         patch('src.api.pci_dss_endpoints.get_network_security_manager', return_value=mock_network_security_manager), \
         patch('src.api.pci_dss_endpoints.get_access_control_manager', return_value=mock_access_control_manager), \
         patch('src.api.pci_dss_endpoints.get_monitoring_system', return_value=mock_monitoring_system):
        yield


class TestComplianceEndpoints:
    """Test compliance assessment endpoints."""
    
    def test_run_compliance_assessment(self, client):
        """Test running compliance assessment."""
        response = client.post(
            "/api/v1/pci-dss/assessment/run",
            json={
                "scope": ["requirement_1", "requirement_2"],
                "requirements": ["1", "2"]
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "assessment_id" in data
        assert data["overall_status"] == "compliant"
        assert data["compliance_score"] == 0.95
        assert "requirements" in data
        assert "recommendations" in data
    
    def test_get_compliance_status(self, client):
        """Test getting compliance status."""
        response = client.get("/api/v1/pci-dss/assessment/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["overall_status"] == "compliant"
        assert data["compliance_score"] == 0.95
    
    def test_get_assessment_history(self, client):
        """Test getting assessment history."""
        response = client.get("/api/v1/pci-dss/assessment/history?limit=5")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "assessments" in data
        assert len(data["assessments"]) > 0


class TestCardDataEndpoints:
    """Test card data protection endpoints."""
    
    def test_detect_card_data(self, client):
        """Test card data detection."""
        response = client.post(
            "/api/v1/pci-dss/card-data/detect",
            json={
                "text": "Customer card number: 4111111111111111"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "detected_data" in data
        assert "risk_level" in data
        assert "recommendations" in data
        assert len(data["detected_data"]) > 0
    
    def test_encrypt_card_data(self, client):
        """Test card data encryption."""
        response = client.post(
            "/api/v1/pci-dss/card-data/encrypt",
            json={
                "data_type": "pan",
                "value": "4111111111111111",
                "algorithm": "aes_256_gcm"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert data["encrypted"] is True
        assert "key_id" in data
        assert "message" in data
    
    def test_get_card_data_compliance(self, client):
        """Test getting card data compliance status."""
        response = client.get("/api/v1/pci-dss/card-data/compliance")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "requirement_3" in data
        assert "requirement_4" in data
        assert "overall_compliance" in data


class TestNetworkEndpoints:
    """Test network security endpoints."""
    
    def test_start_vulnerability_scan(self, client):
        """Test starting vulnerability scan."""
        response = client.post(
            "/api/v1/pci-dss/network/scan",
            json={
                "target_hosts": ["192.168.1.100"],
                "scan_type": "comprehensive"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "scan_id" in data
        assert data["status"] == "completed"
        assert "vulnerabilities_found" in data
        assert "critical_count" in data
    
    def test_get_network_topology(self, client):
        """Test getting network topology."""
        response = client.get("/api/v1/pci-dss/network/topology")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "interfaces" in data
        assert "devices" in data
        assert "subnets" in data
        assert "zones" in data
    
    def test_configure_firewall_rules(self, client):
        """Test configuring firewall rules."""
        rules = [
            {
                "name": "Block HTTP",
                "source_ip": "0.0.0.0",
                "destination_ip": "192.168.1.100",
                "port": 80,
                "protocol": "tcp",
                "action": "deny"
            }
        ]
        
        response = client.post(
            "/api/v1/pci-dss/network/firewall/rules",
            json=rules
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["configured_rules"] == 5
        assert data["failed_rules"] == 0
    
    def test_get_network_compliance(self, client):
        """Test getting network compliance status."""
        response = client.get("/api/v1/pci-dss/network/compliance")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "requirement_1" in data
        assert "requirement_2" in data
        assert "requirement_11" in data


class TestAccessControlEndpoints:
    """Test access control endpoints."""
    
    def test_create_user(self, client):
        """Test user creation."""
        response = client.post(
            "/api/v1/pci-dss/access/users",
            json={
                "username": "testuser",
                "email": "test@example.com",
                "full_name": "Test User",
                "role": "data_processor",
                "password": "SecurePassword123!"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["username"] == "testuser"
        assert data["role"] == "data_processor"
        assert "user_id" in data
        assert "created_at" in data
    
    def test_authenticate_user(self, client):
        """Test user authentication."""
        response = client.post(
            "/api/v1/pci-dss/access/authenticate",
            json={
                "username": "testuser",
                "password": "SecurePassword123!"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["success"] is True
        assert "session_id" in data
        assert "user_id" in data
        assert "expires_at" in data
    
    def test_get_access_compliance(self, client):
        """Test getting access control compliance."""
        response = client.get("/api/v1/pci-dss/access/compliance")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "requirement_7" in data
        assert "requirement_8" in data
    
    def test_get_user_activity_report(self, client):
        """Test getting user activity report."""
        response = client.get("/api/v1/pci-dss/access/users/user_123/activity?days=30")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["user_id"] == "user_123"
        assert "total_access_events" in data
        assert "successful_events" in data
        assert "failed_events" in data


class TestMonitoringEndpoints:
    """Test security monitoring endpoints."""
    
    def test_log_security_event(self, client):
        """Test logging security event."""
        response = client.post(
            "/api/v1/pci-dss/monitoring/events",
            json={
                "event_type": "login_success",
                "user_id": "user_123",
                "resource": "login_system",
                "action": "login",
                "outcome": "success",
                "description": "User logged in successfully"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "event_id" in data
        assert "timestamp" in data
        assert "message" in data
    
    def test_get_security_dashboard(self, client):
        """Test getting security dashboard."""
        response = client.get("/api/v1/pci-dss/monitoring/dashboard")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "timestamp" in data
        assert "summary" in data
        assert "event_statistics" in data
        assert "active_alerts" in data
        assert data["summary"]["total_events_24h"] == 100
    
    def test_get_security_alerts(self, client):
        """Test getting security alerts."""
        response = client.get("/api/v1/pci-dss/monitoring/alerts?status=active&limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "alerts" in data
    
    def test_acknowledge_alert(self, client):
        """Test acknowledging security alert."""
        response = client.post(
            "/api/v1/pci-dss/monitoring/alerts/alert_123/acknowledge?user_id=security_officer"
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["alert_id"] == "alert_123"
        assert data["status"] == "acknowledged"
    
    def test_resolve_alert(self, client):
        """Test resolving security alert."""
        response = client.post(
            "/api/v1/pci-dss/monitoring/alerts/alert_123/resolve",
            params={
                "user_id": "security_officer",
                "resolution_notes": "Issue resolved by blocking IP"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["alert_id"] == "alert_123"
        assert data["status"] == "resolved"
    
    def test_generate_audit_report(self, client):
        """Test generating audit report."""
        start_date = (datetime.utcnow() - timedelta(days=7)).isoformat()
        end_date = datetime.utcnow().isoformat()
        
        response = client.get(
            f"/api/v1/pci-dss/monitoring/reports/audit?start_date={start_date}&end_date={end_date}"
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "report_period" in data
        assert "summary" in data
        assert "event_breakdown" in data


class TestHealthAndStatus:
    """Test health check and status endpoints."""
    
    def test_health_check(self, client):
        """Test system health check."""
        response = client.get("/api/v1/pci-dss/health")
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "services" in data
        
        # Check all services are operational
        for service_status in data["services"].values():
            assert service_status == "operational"
    
    def test_system_overview(self, client):
        """Test getting system overview."""
        response = client.get("/api/v1/pci-dss/status/overview")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "timestamp" in data
        assert "compliance" in data
        assert "security" in data
        assert "system_health" in data
        
        assert data["compliance"]["overall_status"] == "compliant"
        assert data["security"]["total_events_24h"] == 100


class TestErrorHandling:
    """Test error handling in API endpoints."""
    
    def test_invalid_request_data(self, client):
        """Test handling of invalid request data."""
        # Test with invalid JSON
        response = client.post(
            "/api/v1/pci-dss/card-data/detect",
            json={
                "invalid_field": "test"
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_missing_required_fields(self, client):
        """Test handling of missing required fields."""
        response = client.post(
            "/api/v1/pci-dss/access/users",
            json={
                "username": "testuser"
                # Missing required fields
            }
        )
        
        assert response.status_code == 422
    
    @patch('src.api.pci_dss_endpoints.get_compliance_engine')
    def test_service_error_handling(self, mock_get_engine, client):
        """Test handling of service errors."""
        # Mock service to raise exception
        mock_engine = Mock()
        mock_engine.run_comprehensive_assessment = AsyncMock(
            side_effect=Exception("Service error")
        )
        mock_get_engine.return_value = mock_engine
        
        response = client.post("/api/v1/pci-dss/assessment/run", json={})
        
        assert response.status_code == 500
        assert "Assessment failed" in response.json()["detail"]


class TestAuthentication:
    """Test API authentication and authorization."""
    
    def test_protected_endpoint_without_auth(self, client):
        """Test accessing protected endpoint without authentication."""
        # For this test, we'd need to implement actual authentication
        # This is a placeholder for when authentication is added
        pass
    
    def test_invalid_token(self, client):
        """Test accessing endpoint with invalid token."""
        # Placeholder for token validation tests
        pass
    
    def test_insufficient_permissions(self, client):
        """Test accessing endpoint with insufficient permissions."""
        # Placeholder for permission checking tests
        pass


class TestRateLimiting:
    """Test API rate limiting."""
    
    def test_rate_limiting(self, client):
        """Test API rate limiting functionality."""
        # This would test rate limiting if implemented
        # For now, it's a placeholder
        pass


class TestAPIPerformance:
    """Test API performance under load."""
    
    def test_concurrent_requests(self, client):
        """Test handling of concurrent requests."""
        import concurrent.futures
        import threading
        
        def make_request():
            return client.get("/api/v1/pci-dss/health")
        
        # Make 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            responses = [future.result() for future in futures]
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == 200
    
    def test_large_payload_handling(self, client):
        """Test handling of large payloads."""
        # Create large text with many PANs
        large_text = "Test data: " + " 4111111111111111" * 1000
        
        response = client.post(
            "/api/v1/pci-dss/card-data/detect",
            json={"text": large_text}
        )
        
        # Should handle large payload gracefully
        assert response.status_code in [200, 413]  # OK or payload too large


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])