"""
Comprehensive Test Suite for PCI DSS Compliance System

This module contains comprehensive tests for all PCI DSS compliance components.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, List, Any

from src.core.compliance.pci_dss_core import (
    PCIDSSComplianceEngine, PCIControl, PCIAssessment, PCIEnvironment, 
    ControlStatus, AssessmentType
)
from src.core.compliance.card_data_protection import (
    CardDataProtectionManager, CardDataElement, CardDataType, 
    EncryptionAlgorithm, EncryptionKey, KeyManagementStatus
)
from src.core.compliance.network_security import (
    NetworkSecurityManager, FirewallRule, VulnerabilityFinding,
    NetworkZone, ProtocolType, FirewallAction, VulnerabilityLevel
)
from src.core.compliance.access_control import (
    AccessControlManager, User, UserRole, Permission, AccountStatus,
    AuthenticationMethod, Session
)
from src.core.compliance.monitoring_system import (
    SecurityMonitoringSystem, SecurityEvent, SecurityAlert,
    EventType, Severity, AlertStatus
)
from src.core.database.database_manager import DatabaseManager
from src.core.security.encryption import EncryptionManager


class TestPCIDSSCore:
    """Test suite for PCI DSS core compliance engine."""
    
    @pytest.fixture
    def mock_db_manager(self):
        """Mock database manager."""
        return Mock(spec=DatabaseManager)
    
    @pytest.fixture
    def mock_encryption_manager(self):
        """Mock encryption manager."""
        return Mock(spec=EncryptionManager)
    
    @pytest.fixture
    def compliance_engine(self, mock_db_manager, mock_encryption_manager):
        """PCI DSS compliance engine fixture."""
        return PCIDSSComplianceEngine(mock_db_manager, mock_encryption_manager)
    
    @pytest.mark.asyncio
    async def test_comprehensive_assessment(self, compliance_engine):
        """Test comprehensive compliance assessment."""
        # Run assessment
        result = await compliance_engine.run_comprehensive_assessment()
        
        # Verify assessment structure
        assert 'assessment_id' in result
        assert 'overall_status' in result
        assert 'compliance_score' in result
        assert 'requirements' in result
        assert 'recommendations' in result
        
        # Verify all 12 requirements are assessed
        assert len(result['requirements']) == 12
        
        # Verify compliance score is between 0 and 1
        assert 0 <= result['compliance_score'] <= 1
    
    @pytest.mark.asyncio
    async def test_specific_requirement_assessment(self, compliance_engine):
        """Test assessment of specific requirements."""
        # Test requirement 1 (Firewall configuration)
        result = await compliance_engine.assess_requirement(1)
        
        assert result['requirement'] == '1'
        assert 'controls' in result
        assert 'status' in result
        assert result['status'] in ['compliant', 'non_compliant', 'not_applicable']
    
    @pytest.mark.asyncio
    async def test_control_evaluation(self, compliance_engine):
        """Test individual control evaluation."""
        # Create test control
        control = PCIControl(
            control_id="1.1.1",
            title="Test Control",
            requirement="Test firewall configuration",
            testing_procedures=["Test procedure 1"],
            status=ControlStatus.NOT_TESTED
        )
        
        # Evaluate control
        result = await compliance_engine.evaluate_control(control)
        
        assert result['control_id'] == "1.1.1"
        assert 'status' in result
        assert 'findings' in result
        assert 'evidence' in result
    
    def test_compliance_score_calculation(self, compliance_engine):
        """Test compliance score calculation."""
        # Mock assessment results
        requirements = [
            {'status': 'compliant', 'score': 1.0},
            {'status': 'compliant', 'score': 1.0},
            {'status': 'non_compliant', 'score': 0.5},
            {'status': 'compliant', 'score': 1.0}
        ]
        
        score = compliance_engine._calculate_compliance_score(requirements)
        
        # Should be (1.0 + 1.0 + 0.5 + 1.0) / 4 = 0.875
        assert score == 0.875
    
    @pytest.mark.asyncio
    async def test_remediation_plan_generation(self, compliance_engine):
        """Test remediation plan generation."""
        # Mock failed controls
        failed_controls = [
            PCIControl(
                control_id="1.1.1",
                title="Firewall Configuration",
                requirement="Configure firewall properly",
                testing_procedures=["Test firewall rules"],
                status=ControlStatus.FAIL
            )
        ]
        
        plan = await compliance_engine.generate_remediation_plan(failed_controls)
        
        assert 'plan_id' in plan
        assert 'actions' in plan
        assert len(plan['actions']) > 0
        assert 'estimated_effort' in plan


class TestCardDataProtection:
    """Test suite for card data protection."""
    
    @pytest.fixture
    def mock_db_manager(self):
        return Mock(spec=DatabaseManager)
    
    @pytest.fixture
    def mock_encryption_manager(self):
        return Mock(spec=EncryptionManager)
    
    @pytest.fixture
    def mock_compliance_engine(self):
        return Mock(spec=PCIDSSComplianceEngine)
    
    @pytest.fixture
    def card_protection_manager(self, mock_db_manager, mock_encryption_manager, mock_compliance_engine):
        return CardDataProtectionManager(
            mock_db_manager, mock_encryption_manager, mock_compliance_engine
        )
    
    @pytest.mark.asyncio
    async def test_pan_detection(self, card_protection_manager):
        """Test PAN detection in text."""
        test_text = "Customer card number is 4111111111111111 with expiry 12/25"
        
        detected_data = await card_protection_manager.detect_card_data(test_text)
        
        # Should detect PAN
        pan_detections = [d for d in detected_data if d['type'] == CardDataType.PRIMARY_ACCOUNT_NUMBER]
        assert len(pan_detections) > 0
        assert pan_detections[0]['value'] == '4111111111111111'
    
    @pytest.mark.asyncio
    async def test_cvv_detection(self, card_protection_manager):
        """Test CVV detection in text."""
        test_text = "CVV: 123"
        
        detected_data = await card_protection_manager.detect_card_data(test_text)
        
        # Should detect CVV
        cvv_detections = [d for d in detected_data if d['type'] == CardDataType.CVV]
        assert len(cvv_detections) > 0
        assert cvv_detections[0]['value'] == '123'
    
    @pytest.mark.asyncio
    async def test_data_encryption(self, card_protection_manager):
        """Test card data encryption."""
        # Create card data element
        card_data = CardDataElement(
            data_type=CardDataType.PRIMARY_ACCOUNT_NUMBER,
            value="4111111111111111"
        )
        
        # Encrypt data
        encrypted_data = await card_protection_manager.encrypt_card_data(card_data)
        
        assert encrypted_data.encrypted is True
        assert encrypted_data.encryption_key_id is not None
        assert encrypted_data.value != "4111111111111111"  # Should be encrypted
    
    @pytest.mark.asyncio
    async def test_prohibited_data_storage(self, card_protection_manager):
        """Test that prohibited data (SAD) cannot be stored."""
        # Create CVV data element (prohibited)
        card_data = CardDataElement(
            data_type=CardDataType.CVV,
            value="123"
        )
        
        # Should raise exception
        with pytest.raises(ValueError, match="must never be stored"):
            await card_protection_manager.encrypt_card_data(card_data)
    
    def test_luhn_algorithm_validation(self, card_protection_manager):
        """Test Luhn algorithm validation for PAN."""
        # Valid test PAN
        valid_pan = "4111111111111111"
        assert card_protection_manager._validate_luhn(valid_pan) is True
        
        # Invalid PAN
        invalid_pan = "4111111111111112"
        assert card_protection_manager._validate_luhn(invalid_pan) is False
    
    @pytest.mark.asyncio
    async def test_data_masking(self, card_protection_manager):
        """Test card data masking."""
        card_data = CardDataElement(
            data_type=CardDataType.PRIMARY_ACCOUNT_NUMBER,
            value="4111111111111111"
        )
        
        masked_value = await card_protection_manager.mask_card_data(card_data)
        
        # Should show first 6 and last 4 digits
        assert masked_value == "411111******1111"
    
    @pytest.mark.asyncio
    async def test_key_rotation(self, card_protection_manager):
        """Test encryption key rotation."""
        # Create initial key
        key = await card_protection_manager._create_encryption_key(EncryptionAlgorithm.AES_256_GCM)
        
        # Set key as expired
        key.expires_at = datetime.utcnow() - timedelta(hours=1)
        card_protection_manager.encryption_keys[key.key_id] = key
        
        # Perform rotation
        rotation_result = await card_protection_manager.rotate_encryption_keys()
        
        assert rotation_result['rotated_keys'] == 1 or len(rotation_result['rotated_keys']) > 0
    
    @pytest.mark.asyncio
    async def test_compliance_assessment(self, card_protection_manager):
        """Test card data protection compliance assessment."""
        status = await card_protection_manager.get_compliance_status()
        
        assert 'requirement_3' in status
        assert 'requirement_4' in status
        assert 'overall_compliance' in status


class TestNetworkSecurity:
    """Test suite for network security."""
    
    @pytest.fixture
    def mock_db_manager(self):
        return Mock(spec=DatabaseManager)
    
    @pytest.fixture
    def mock_compliance_engine(self):
        return Mock(spec=PCIDSSComplianceEngine)
    
    @pytest.fixture
    def network_manager(self, mock_db_manager, mock_compliance_engine):
        return NetworkSecurityManager(mock_db_manager, mock_compliance_engine)
    
    @pytest.mark.asyncio
    async def test_firewall_rule_configuration(self, network_manager):
        """Test firewall rule configuration."""
        rules = [
            {
                'name': 'Block HTTP',
                'source_ip': '0.0.0.0',
                'destination_ip': '192.168.1.100',
                'port': 80,
                'protocol': 'tcp',
                'action': 'deny'
            }
        ]
        
        result = await network_manager.configure_firewall_rules(rules)
        
        assert result['configured_rules'] == 1
        assert result['failed_rules'] == 0
    
    @pytest.mark.asyncio
    async def test_firewall_rule_validation(self, network_manager):
        """Test firewall rule validation."""
        # Valid rule
        valid_rule = FirewallRule(
            rule_id="test_rule",
            name="Test Rule",
            source_ip="192.168.1.1",
            destination_ip="192.168.1.100",
            port=80,
            protocol=ProtocolType.TCP,
            action=FirewallAction.ALLOW
        )
        
        is_valid = await network_manager._validate_firewall_rule(valid_rule)
        assert is_valid is True
        
        # Invalid rule (invalid IP)
        invalid_rule = FirewallRule(
            rule_id="test_rule",
            name="Test Rule",
            source_ip="invalid_ip",
            destination_ip="192.168.1.100",
            port=80,
            protocol=ProtocolType.TCP,
            action=FirewallAction.ALLOW
        )
        
        is_valid = await network_manager._validate_firewall_rule(invalid_rule)
        assert is_valid is False
    
    @pytest.mark.asyncio 
    async def test_vulnerability_scanning(self, network_manager):
        """Test vulnerability scanning."""
        with patch('nmap.PortScanner') as mock_nmap:
            # Mock nmap results
            mock_scanner = Mock()
            mock_scanner.scan.return_value = {}
            mock_scanner.all_hosts.return_value = ['192.168.1.100']
            mock_scanner.__getitem__.return_value = {
                'state': lambda: 'up',
                'tcp': {
                    80: {'name': 'http', 'version': '2.2', 'product': 'Apache'}
                }
            }
            mock_nmap.return_value = mock_scanner
            
            scan_result = await network_manager.perform_vulnerability_scan(['192.168.1.100'])
            
            assert 'scan_id' in scan_result
            assert scan_result['targets'] == ['192.168.1.100']
            assert 'vulnerabilities' in scan_result
    
    @pytest.mark.asyncio
    async def test_network_discovery(self, network_manager):
        """Test network topology discovery."""
        with patch('psutil.net_if_addrs') as mock_interfaces:
            # Mock network interfaces
            mock_interfaces.return_value = {
                'eth0': [
                    Mock(family=2, address='192.168.1.50', netmask='255.255.255.0')
                ]
            }
            
            topology = await network_manager.discover_network_topology()
            
            assert 'interfaces' in topology
            assert 'devices' in topology
            assert 'subnets' in topology
    
    @pytest.mark.asyncio
    async def test_wireless_security_assessment(self, network_manager):
        """Test wireless security assessment."""
        assessment = await network_manager.assess_wireless_security()
        
        assert 'networks_discovered' in assessment
        assert 'secure_networks' in assessment
        assert 'insecure_networks' in assessment
        assert 'vulnerabilities' in assessment
    
    @pytest.mark.asyncio
    async def test_compliance_assessment(self, network_manager):
        """Test network security compliance assessment."""
        status = await network_manager.get_compliance_status()
        
        assert 'requirement_1' in status
        assert 'requirement_2' in status
        assert 'requirement_11' in status
        assert 'overall_compliance' in status


class TestAccessControl:
    """Test suite for access control."""
    
    @pytest.fixture
    def mock_db_manager(self):
        return Mock(spec=DatabaseManager)
    
    @pytest.fixture
    def mock_compliance_engine(self):
        return Mock(spec=PCIDSSComplianceEngine)
    
    @pytest.fixture
    def access_manager(self, mock_db_manager, mock_compliance_engine):
        return AccessControlManager(mock_db_manager, mock_compliance_engine)
    
    @pytest.mark.asyncio
    async def test_user_creation(self, access_manager):
        """Test user account creation."""
        user = await access_manager.create_user(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.DATA_PROCESSOR,
            password="SecurePassword123!"
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.DATA_PROCESSOR
        assert user.password_hash is not None
        assert user.user_id in access_manager.users
    
    @pytest.mark.asyncio
    async def test_user_authentication(self, access_manager):
        """Test user authentication."""
        # Create user first
        await access_manager.create_user(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.DATA_PROCESSOR,
            password="SecurePassword123!"
        )
        
        # Set user as active
        user = list(access_manager.users.values())[0]
        user.status = AccountStatus.ACTIVE
        
        # Authenticate
        session = await access_manager.authenticate_user(
            username="testuser",
            password="SecurePassword123!",
            ip_address="192.168.1.100",
            user_agent="Test Agent"
        )
        
        assert session is not None
        assert session.user_id == user.user_id
        assert session.active is True
    
    @pytest.mark.asyncio
    async def test_authentication_failure(self, access_manager):
        """Test authentication failure."""
        session = await access_manager.authenticate_user(
            username="nonexistent",
            password="wrongpassword",
            ip_address="192.168.1.100",
            user_agent="Test Agent"
        )
        
        assert session is None
    
    @pytest.mark.asyncio
    async def test_permission_checking(self, access_manager):
        """Test permission checking."""
        # Create user
        user = await access_manager.create_user(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.DATA_PROCESSOR,
            password="SecurePassword123!"
        )
        
        # Check permission that user should have
        has_permission = await access_manager.check_permission(
            user.user_id,
            Permission.READ_PII
        )
        assert has_permission is True
        
        # Check permission that user should not have
        has_permission = await access_manager.check_permission(
            user.user_id,
            Permission.MANAGE_USERS
        )
        assert has_permission is False
    
    def test_password_validation(self, access_manager):
        """Test password policy validation."""
        # Valid password
        assert access_manager._validate_password("SecurePassword123!") is True
        
        # Too short
        assert access_manager._validate_password("Short1!") is False
        
        # No uppercase
        assert access_manager._validate_password("securepassword123!") is False
        
        # No special characters
        assert access_manager._validate_password("SecurePassword123") is False
    
    @pytest.mark.asyncio
    async def test_session_validation(self, access_manager):
        """Test session validation."""
        # Create user and session
        user = await access_manager.create_user(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.DATA_PROCESSOR,
            password="SecurePassword123!"
        )
        user.status = AccountStatus.ACTIVE
        
        session = await access_manager._create_session(user, "192.168.1.100", "Test Agent")
        
        # Validate session
        validated_user = await access_manager.validate_session(session.session_id)
        assert validated_user is not None
        assert validated_user.user_id == user.user_id
        
        # Invalidate session by expiring it
        session.expires_at = datetime.utcnow() - timedelta(minutes=1)
        
        validated_user = await access_manager.validate_session(session.session_id)
        assert validated_user is None
    
    @pytest.mark.asyncio
    async def test_access_request_workflow(self, access_manager):
        """Test privileged access request workflow."""
        # Create user
        user = await access_manager.create_user(
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            role=UserRole.DATA_PROCESSOR,
            password="SecurePassword123!"
        )
        
        # Request access
        request = await access_manager.request_access(
            user_id=user.user_id,
            permission=Permission.DELETE_PII,
            resource="test_resource",
            justification="Testing purposes"
        )
        
        assert request.user_id == user.user_id
        assert request.permission == Permission.DELETE_PII
        assert request.approved is False
        
        # Create approver
        approver = await access_manager.create_user(
            username="approver",
            email="approver@example.com",
            full_name="Approver User",
            role=UserRole.SECURITY_OFFICER,
            password="SecurePassword123!"
        )
        
        # Approve request
        approved = await access_manager.approve_access_request(
            request.request_id,
            approver.user_id
        )
        
        assert approved is True
        assert request.approved is True
        assert request.approved_by == approver.user_id
    
    @pytest.mark.asyncio
    async def test_compliance_assessment(self, access_manager):
        """Test access control compliance assessment."""
        status = await access_manager.get_compliance_status()
        
        assert 'requirement_7' in status
        assert 'requirement_8' in status
        assert 'overall_compliance' in status


class TestSecurityMonitoring:
    """Test suite for security monitoring system."""
    
    @pytest.fixture
    def mock_db_manager(self):
        return Mock(spec=DatabaseManager)
    
    @pytest.fixture
    def mock_compliance_engine(self):
        return Mock(spec=PCIDSSComplianceEngine)
    
    @pytest.fixture
    def monitoring_system(self, mock_db_manager, mock_compliance_engine):
        return SecurityMonitoringSystem(mock_db_manager, mock_compliance_engine)
    
    @pytest.mark.asyncio
    async def test_security_event_logging(self, monitoring_system):
        """Test security event logging."""
        event = await monitoring_system.log_security_event(
            event_type=EventType.LOGIN_SUCCESS,
            user_id="test_user",
            source_ip="192.168.1.100",
            resource="login_system",
            action="login",
            outcome="success",
            description="User logged in successfully"
        )
        
        assert event.event_type == EventType.LOGIN_SUCCESS
        assert event.user_id == "test_user"
        assert event.outcome == "success"
        assert event.event_id in [e.event_id for e in monitoring_system.security_events]
    
    @pytest.mark.asyncio
    async def test_monitoring_rule_evaluation(self, monitoring_system):
        """Test monitoring rule evaluation."""
        # Get default rule
        rule = monitoring_system.monitoring_rules['failed_login_attempts']
        
        # Create test event
        event = SecurityEvent(
            event_id="test_event",
            event_type=EventType.LOGIN_FAILURE,
            timestamp=datetime.utcnow(),
            user_id="test_user",
            source_ip="192.168.1.100",
            user_agent="Test Agent",
            resource="login_system",
            action="login",
            outcome="failure",
            severity=Severity.MEDIUM,
            description="Login failed"
        )
        
        # Add multiple events to trigger rule
        for _ in range(6):
            monitoring_system.security_events.append(event)
        
        # Evaluate rule
        triggered = await monitoring_system._evaluate_monitoring_rule(rule, event)
        assert triggered is True
    
    @pytest.mark.asyncio
    async def test_alert_generation(self, monitoring_system):
        """Test security alert generation."""
        # Get rule
        rule = monitoring_system.monitoring_rules['failed_login_attempts']
        
        # Create triggering event
        event = SecurityEvent(
            event_id="test_event",
            event_type=EventType.LOGIN_FAILURE,
            timestamp=datetime.utcnow(),
            user_id="test_user",
            source_ip="192.168.1.100",
            user_agent="Test Agent",
            resource="login_system",
            action="login",
            outcome="failure",
            severity=Severity.MEDIUM,
            description="Login failed"
        )
        
        # Trigger alert
        await monitoring_system._trigger_alert(rule, event)
        
        assert len(monitoring_system.security_alerts) > 0
        alert = list(monitoring_system.security_alerts.values())[0]
        assert alert.alert_type == rule.name
        assert alert.severity == rule.severity
        assert alert.status == AlertStatus.ACTIVE
    
    @pytest.mark.asyncio
    async def test_alert_acknowledgment(self, monitoring_system):
        """Test alert acknowledgment."""
        # Create alert
        rule = monitoring_system.monitoring_rules['failed_login_attempts']
        event = SecurityEvent(
            event_id="test_event",
            event_type=EventType.LOGIN_FAILURE,
            timestamp=datetime.utcnow(),
            user_id="test_user",
            source_ip="192.168.1.100",
            user_agent="Test Agent",
            resource="login_system",
            action="login",
            outcome="failure",
            severity=Severity.MEDIUM,
            description="Login failed"
        )
        
        await monitoring_system._trigger_alert(rule, event)
        alert_id = list(monitoring_system.security_alerts.keys())[0]
        
        # Acknowledge alert
        success = await monitoring_system.acknowledge_alert(alert_id, "admin_user")
        
        assert success is True
        alert = monitoring_system.security_alerts[alert_id]
        assert alert.status == AlertStatus.ACKNOWLEDGED
        assert alert.acknowledged_by == "admin_user"
    
    @pytest.mark.asyncio
    async def test_security_dashboard(self, monitoring_system):
        """Test security dashboard generation."""
        # Add some test events
        await monitoring_system.log_security_event(
            event_type=EventType.LOGIN_SUCCESS,
            user_id="test_user",
            source_ip="192.168.1.100",
            resource="login_system",
            action="login",
            outcome="success",
            description="User logged in"
        )
        
        dashboard = await monitoring_system.get_security_dashboard()
        
        assert 'timestamp' in dashboard
        assert 'summary' in dashboard
        assert 'event_statistics' in dashboard
        assert 'active_alerts' in dashboard
        assert 'recent_high_risk_events' in dashboard
        assert 'system_metrics' in dashboard
    
    @pytest.mark.asyncio
    async def test_audit_report_generation(self, monitoring_system):
        """Test audit report generation."""
        # Add test events
        await monitoring_system.log_security_event(
            event_type=EventType.PII_ACCESS,
            user_id="test_user",
            source_ip="192.168.1.100",
            resource="pii_database",
            action="read",
            outcome="success",
            description="PII data accessed"
        )
        
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)
        
        report = await monitoring_system.generate_audit_report(start_date, end_date)
        
        assert 'report_period' in report
        assert 'summary' in report
        assert 'event_breakdown' in report
        assert 'severity_breakdown' in report
        assert report['summary']['total_events'] > 0
    
    @pytest.mark.asyncio
    async def test_compliance_assessment(self, monitoring_system):
        """Test monitoring compliance assessment."""
        status = await monitoring_system.get_compliance_status()
        
        assert 'requirement_10' in status
        assert 'requirement_12' in status
        assert 'overall_compliance' in status


class TestIntegration:
    """Integration tests for PCI DSS system components."""
    
    @pytest.fixture
    def mock_db_manager(self):
        return Mock(spec=DatabaseManager)
    
    @pytest.fixture
    def mock_encryption_manager(self):
        return Mock(spec=EncryptionManager)
    
    @pytest.fixture
    def integrated_system(self, mock_db_manager, mock_encryption_manager):
        """Setup integrated system with all components."""
        compliance_engine = PCIDSSComplianceEngine(mock_db_manager, mock_encryption_manager)
        
        card_protection = CardDataProtectionManager(
            mock_db_manager, mock_encryption_manager, compliance_engine
        )
        
        network_security = NetworkSecurityManager(mock_db_manager, compliance_engine)
        
        access_control = AccessControlManager(mock_db_manager, compliance_engine)
        
        monitoring_system = SecurityMonitoringSystem(mock_db_manager, compliance_engine)
        
        return {
            'compliance_engine': compliance_engine,
            'card_protection': card_protection,
            'network_security': network_security,
            'access_control': access_control,
            'monitoring_system': monitoring_system
        }
    
    @pytest.mark.asyncio
    async def test_end_to_end_card_data_processing(self, integrated_system):
        """Test end-to-end card data processing workflow."""
        card_manager = integrated_system['card_protection']
        monitoring = integrated_system['monitoring_system']
        
        # Detect card data
        test_text = "Customer card: 4111111111111111"
        detected_data = await card_manager.detect_card_data(test_text)
        
        assert len(detected_data) > 0
        
        # Create and encrypt card data
        from src.core.compliance.card_data_protection import CardDataElement
        card_data = CardDataElement(
            data_type=CardDataType.PRIMARY_ACCOUNT_NUMBER,
            value="4111111111111111"
        )
        
        encrypted_data = await card_manager.encrypt_card_data(card_data)
        assert encrypted_data.encrypted is True
        
        # Log the operation
        await monitoring.log_security_event(
            event_type=EventType.PII_ACCESS,
            user_id="test_user",
            source_ip="192.168.1.100",
            resource="card_data",
            action="encrypt",
            outcome="success",
            description="Card data encrypted"
        )
        
        # Verify event was logged
        assert len(monitoring.security_events) > 0
        assert monitoring.security_events[-1].event_type == EventType.PII_ACCESS
    
    @pytest.mark.asyncio
    async def test_compliance_workflow_integration(self, integrated_system):
        """Test integrated compliance assessment workflow."""
        compliance_engine = integrated_system['compliance_engine']
        
        # Run full assessment
        assessment = await compliance_engine.run_comprehensive_assessment()
        
        # Verify all requirements assessed
        assert len(assessment['requirements']) == 12
        
        # Check individual component compliance
        card_status = await integrated_system['card_protection'].get_compliance_status()
        network_status = await integrated_system['network_security'].get_compliance_status()
        access_status = await integrated_system['access_control'].get_compliance_status()
        monitoring_status = await integrated_system['monitoring_system'].get_compliance_status()
        
        # All should have compliance status
        for status in [card_status, network_status, access_status, monitoring_status]:
            assert 'overall_compliance' in status
            assert status['overall_compliance'] in ['compliant', 'non_compliant']
    
    @pytest.mark.asyncio
    async def test_security_incident_response(self, integrated_system):
        """Test integrated security incident response."""
        monitoring = integrated_system['monitoring_system']
        access_control = integrated_system['access_control']
        
        # Simulate security incident (multiple failed logins)
        for i in range(6):
            await monitoring.log_security_event(
                event_type=EventType.LOGIN_FAILURE,
                user_id="attacker",
                source_ip="192.168.1.200",
                resource="login_system",
                action="login",
                outcome="failure",
                description=f"Failed login attempt #{i+1}"
            )
        
        # Should trigger alert
        assert len(monitoring.security_alerts) > 0
        
        # Get the alert
        alert = list(monitoring.security_alerts.values())[0]
        assert alert.status == AlertStatus.ACTIVE
        assert alert.severity in [Severity.HIGH, Severity.CRITICAL]
        
        # Simulate security response
        success = await monitoring.acknowledge_alert(alert.alert_id, "security_officer")
        assert success is True
        
        # Resolve the alert
        success = await monitoring.resolve_alert(
            alert.alert_id, 
            "security_officer",
            "Blocked IP address and enhanced monitoring implemented"
        )
        assert success is True
        
        alert = monitoring.security_alerts[alert.alert_id]
        assert alert.status == AlertStatus.RESOLVED


# Performance and load testing
class TestPerformance:
    """Performance tests for PCI DSS system."""
    
    @pytest.mark.asyncio
    async def test_bulk_card_data_detection_performance(self):
        """Test performance of bulk card data detection."""
        import time
        
        # Setup
        mock_db = Mock(spec=DatabaseManager)
        mock_encryption = Mock(spec=EncryptionManager)
        mock_compliance = Mock(spec=PCIDSSComplianceEngine)
        
        card_manager = CardDataProtectionManager(mock_db, mock_encryption, mock_compliance)
        
        # Test data with multiple PANs
        test_texts = [
            f"Card {i}: 4{str(i).zfill(15)}" for i in range(100)
        ]
        
        start_time = time.time()
        
        for text in test_texts:
            await card_manager.detect_card_data(text)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 100 texts in reasonable time (< 5 seconds)
        assert processing_time < 5.0
        print(f"Processed 100 texts in {processing_time:.2f} seconds")
    
    @pytest.mark.asyncio
    async def test_monitoring_system_load(self):
        """Test monitoring system under load."""
        import time
        
        mock_db = Mock(spec=DatabaseManager)
        mock_compliance = Mock(spec=PCIDSSComplianceEngine)
        
        monitoring = SecurityMonitoringSystem(mock_db, mock_compliance)
        
        start_time = time.time()
        
        # Log 1000 events
        for i in range(1000):
            await monitoring.log_security_event(
                event_type=EventType.PII_ACCESS,
                user_id=f"user_{i % 10}",
                source_ip=f"192.168.1.{i % 255}",
                resource="test_resource",
                action="access",
                outcome="success",
                description=f"Test event {i}"
            )
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should log 1000 events in reasonable time
        assert processing_time < 10.0
        assert len(monitoring.security_events) == 1000
        print(f"Logged 1000 events in {processing_time:.2f} seconds")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])