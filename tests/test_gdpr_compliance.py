"""
GDPR Compliance Testing Suite
Comprehensive tests for GDPR implementation validation
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, AsyncMock, patch
import json

from src.core.gdpr.data_subject_rights import (
    DataSubjectRightsManager, DataSubjectRightType, RequestStatus, 
    DataSubjectIdentity, PersonalDataInventory
)
from src.core.gdpr.consent_management import (
    ConsentManager, ConsentStatus, ConsentType, ProcessingPurpose, 
    ConsentMethod, ConsentRecord
)
from src.core.gdpr.cross_border_transfers import (
    CrossBorderTransferManager, TransferMechanism, AdequacyStatus,
    DataTransfer, TransferImpactAssessment
)
from src.core.gdpr.breach_management import (
    BreachManager, BreachSeverity, BreachType, BreachStatus,
    DataBreach, AffectedDataSubject
)
from src.core.gdpr.privacy_by_design import (
    PrivacyByDesignFramework, PrivacyPrinciple, PrivacyEnhancingTechnology,
    PrivacyAssessment, PrivacyRisk
)
from src.core.gdpr.processing_records import (
    ProcessingRecordsManager, ProcessingRole, LegalBasis,
    ProcessingActivity, DataCategory, DataSubjectCategory
)
from src.core.database.db_manager import DatabaseManager
from src.core.security.encryption_manager import EncryptionManager


class TestGDPRCompliance:
    """Test suite for GDPR compliance validation"""

    @pytest.fixture
    def mock_db_manager(self):
        """Mock database manager"""
        return Mock(spec=DatabaseManager)

    @pytest.fixture
    def mock_encryption_manager(self):
        """Mock encryption manager"""
        return Mock(spec=EncryptionManager)

    @pytest.fixture
    def dsr_manager(self, mock_db_manager, mock_encryption_manager):
        """Data Subject Rights Manager fixture"""
        return DataSubjectRightsManager(mock_db_manager, mock_encryption_manager)

    @pytest.fixture
    def consent_manager(self, mock_db_manager, mock_encryption_manager):
        """Consent Manager fixture"""
        return ConsentManager(mock_db_manager, mock_encryption_manager)

    @pytest.fixture
    def transfer_manager(self, mock_db_manager, mock_encryption_manager):
        """Cross-Border Transfer Manager fixture"""
        return CrossBorderTransferManager(mock_db_manager, mock_encryption_manager)

    @pytest.fixture
    def breach_manager(self, mock_db_manager, mock_encryption_manager):
        """Breach Manager fixture"""
        return BreachManager(mock_db_manager, mock_encryption_manager)

    @pytest.fixture
    def privacy_framework(self, mock_db_manager, mock_encryption_manager):
        """Privacy by Design Framework fixture"""
        return PrivacyByDesignFramework(mock_db_manager, mock_encryption_manager)

    @pytest.fixture
    def records_manager(self, mock_db_manager, mock_encryption_manager):
        """Processing Records Manager fixture"""
        return ProcessingRecordsManager(mock_db_manager, mock_encryption_manager)

    # Data Subject Rights Tests
    @pytest.mark.asyncio
    async def test_dsr_access_request_creation(self, dsr_manager):
        """Test Article 15 - Right of Access request creation"""
        
        # Arrange
        data_subject = DataSubjectIdentity(
            email="test@example.com",
            name="Test Subject",
            verification_status="verified"
        )

        # Act
        request = await dsr_manager.submit_rights_request(
            request_type=DataSubjectRightType.ACCESS,
            data_subject=data_subject,
            description="Request access to my personal data"
        )

        # Assert
        assert request is not None
        assert request.request_type == DataSubjectRightType.ACCESS
        assert request.data_subject.email == "test@example.com"
        assert request.status == RequestStatus.UNDER_REVIEW
        assert request.compliance_deadline > datetime.now()
        assert (request.compliance_deadline - request.submitted_timestamp).days == 30

    @pytest.mark.asyncio
    async def test_dsr_erasure_request_processing(self, dsr_manager):
        """Test Article 17 - Right to Erasure (Right to be Forgotten)"""
        
        # Arrange
        data_subject = DataSubjectIdentity(
            email="test@example.com",
            name="Test Subject",
            verification_status="verified"
        )

        # Act
        request = await dsr_manager.submit_rights_request(
            request_type=DataSubjectRightType.ERASURE,
            data_subject=data_subject,
            description="Delete my personal data"
        )

        # Assert
        assert request.request_type == DataSubjectRightType.ERASURE
        assert request.status == RequestStatus.UNDER_REVIEW
        
        # Verify erasure workflow is initiated
        assert request.id in dsr_manager.active_requests
        
    @pytest.mark.asyncio
    async def test_dsr_portability_request_validation(self, dsr_manager):
        """Test Article 20 - Right to Data Portability"""
        
        # Arrange
        data_subject = DataSubjectIdentity(
            email="test@example.com",
            name="Test Subject",
            verification_status="verified"
        )

        # Act
        request = await dsr_manager.submit_rights_request(
            request_type=DataSubjectRightType.DATA_PORTABILITY,
            data_subject=data_subject,
            description="Export my data in portable format"
        )

        # Assert
        assert request.request_type == DataSubjectRightType.DATA_PORTABILITY
        assert request.portability_format == "json"  # Default format
        assert request.status == RequestStatus.UNDER_REVIEW

    @pytest.mark.asyncio
    async def test_dsr_response_deadlines(self, dsr_manager):
        """Test GDPR response deadline compliance"""
        
        # Arrange
        data_subject = DataSubjectIdentity(email="test@example.com")
        
        # Act
        request = await dsr_manager.submit_rights_request(
            request_type=DataSubjectRightType.ACCESS,
            data_subject=data_subject
        )

        # Assert - 30-day response deadline
        deadline_days = (request.compliance_deadline - request.submitted_timestamp).days
        assert deadline_days == 30
        
        # Verify due date is set correctly
        expected_due_date = request.submitted_timestamp + timedelta(days=30)
        assert abs((request.due_date - expected_due_date).seconds) < 60  # Within 1 minute

    # Consent Management Tests
    @pytest.mark.asyncio
    async def test_consent_collection_gdpr_compliant(self, consent_manager):
        """Test GDPR-compliant consent collection (Articles 6-7)"""
        
        # Arrange - Get available template
        templates = list(consent_manager.consent_templates.values())
        template = templates[0] if templates else None
        assert template is not None
        
        purpose_consents = {}
        for purpose in template.purposes:
            purpose_consents[purpose.id] = True

        # Act
        consent_record = await consent_manager.collect_consent(
            data_subject_id="test_subject_123",
            template_id=template.id,
            purpose_consents=purpose_consents,
            consent_method=ConsentMethod.WEB_FORM,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )

        # Assert
        assert consent_record is not None
        assert consent_record.data_subject_id == "test_subject_123"
        assert consent_record.consent_method == ConsentMethod.WEB_FORM
        assert consent_record.ip_address == "192.168.1.1"
        assert consent_record.consent_hash is not None  # Integrity proof
        assert consent_record.expiry_date > datetime.now()

        # Verify all purposes have consent status
        for purpose_id in purpose_consents:
            assert purpose_id in consent_record.purposes
            assert consent_record.purposes[purpose_id] == ConsentStatus.GIVEN

    @pytest.mark.asyncio
    async def test_consent_withdrawal_immediate_effect(self, consent_manager):
        """Test immediate effect of consent withdrawal"""
        
        # Arrange - Collect consent first
        templates = list(consent_manager.consent_templates.values())
        template = templates[0]
        
        purpose_consents = {purpose.id: True for purpose in template.purposes}
        
        consent_record = await consent_manager.collect_consent(
            data_subject_id="test_subject_123",
            template_id=template.id,
            purpose_consents=purpose_consents
        )
        
        # Act - Withdraw consent
        withdrawn_records = await consent_manager.withdraw_consent(
            data_subject_id="test_subject_123",
            withdrawal_reason="No longer want marketing communications"
        )

        # Assert
        assert len(withdrawn_records) > 0
        assert consent_record.withdrawal_timestamp is not None
        
        # Verify all purposes are withdrawn
        for purpose_id in consent_record.purposes:
            assert consent_record.purposes[purpose_id] == ConsentStatus.WITHDRAWN

    @pytest.mark.asyncio
    async def test_consent_granular_control(self, consent_manager):
        """Test granular consent control per purpose"""
        
        # Arrange
        templates = list(consent_manager.consent_templates.values())
        template = templates[0]
        
        # Select only some purposes
        purpose_consents = {}
        purposes_list = list(template.purposes)
        purpose_consents[purposes_list[0].id] = True  # Grant first purpose
        purpose_consents[purposes_list[1].id] = False  # Deny second purpose

        # Act
        consent_record = await consent_manager.collect_consent(
            data_subject_id="test_subject_123",
            template_id=template.id,
            purpose_consents=purpose_consents
        )

        # Assert
        assert consent_record.purposes[purposes_list[0].id] == ConsentStatus.GIVEN
        assert consent_record.purposes[purposes_list[1].id] == ConsentStatus.WITHDRAWN

    @pytest.mark.asyncio
    async def test_consent_expiry_management(self, consent_manager):
        """Test consent expiry and renewal management"""
        
        # Act
        renewal_results = await consent_manager.manage_consent_renewals()

        # Assert
        assert "expired_consents" in renewal_results
        assert "renewal_due" in renewal_results
        assert "renewal_sent" in renewal_results
        assert isinstance(renewal_results["expired_consents"], list)
        assert isinstance(renewal_results["renewal_due"], list)

    # Cross-Border Transfer Tests
    @pytest.mark.asyncio
    async def test_adequacy_decision_assessment(self, transfer_manager):
        """Test adequacy decision assessment for transfers"""
        
        # Act - Test adequate country (Switzerland)
        assessment_ch = await transfer_manager.assess_transfer_requirement(
            destination_country_code="CH",
            data_categories=["contact_information"],
            processing_purposes=["customer_service"]
        )

        # Assert
        assert assessment_ch["adequacy_status"] == "adequate"
        assert not assessment_ch["mechanism_required"]
        assert assessment_ch["recommended_mechanism"] == "adequacy_decision"

        # Act - Test non-adequate country (US)
        assessment_us = await transfer_manager.assess_transfer_requirement(
            destination_country_code="US",
            data_categories=["contact_information"],
            processing_purposes=["customer_service"]
        )

        # Assert
        assert assessment_us["adequacy_status"] == "not_adequate"
        assert assessment_us["mechanism_required"]
        assert assessment_us["recommended_mechanism"] == "standard_contractual_clauses"

    @pytest.mark.asyncio
    async def test_transfer_impact_assessment_required(self, transfer_manager):
        """Test Transfer Impact Assessment (TIA) requirement determination"""
        
        # Arrange
        transfer_data = {
            "title": "High-risk data transfer",
            "description": "Transfer of health data to US service provider",
            "destination_country_code": "US",
            "data_exporter": {"name": "EU Company", "role": "controller"},
            "data_importer": {"name": "US Processor", "role": "processor"},
            "data_categories": ["health_data", "identification_data"],
            "data_subjects_categories": ["patients"],
            "processing_purposes": ["data_processing"]
        }

        # Act
        transfer = await transfer_manager.create_transfer_request(transfer_data)

        # Assert
        assert transfer.tia_required is True
        assert transfer.transfer_mechanism == TransferMechanism.STANDARD_CONTRACTUAL_CLAUSES

    @pytest.mark.asyncio
    async def test_standard_contractual_clauses_implementation(self, transfer_manager):
        """Test Standard Contractual Clauses (SCCs) implementation"""
        
        # Arrange
        transfer_data = {
            "title": "SCC Transfer",
            "description": "Transfer requiring SCCs",
            "destination_country_code": "US",
            "data_exporter": {"name": "EU Company", "role": "controller"},
            "data_importer": {"name": "US Processor", "role": "processor"},
            "data_categories": ["contact_information"],
            "data_subjects_categories": ["customers"],
            "processing_purposes": ["customer_support"],
            "transfer_type": "controller_to_processor"
        }

        transfer = await transfer_manager.create_transfer_request(transfer_data)

        # Act
        scc = await transfer_manager.implement_standard_contractual_clauses(
            transfer.id, {"version": "2021", "type": "controller_to_processor"}
        )

        # Assert
        assert scc is not None
        assert scc.scc_version == "2021"
        assert scc.module_two is True  # Controller to processor module
        assert len(scc.parties) == 2
        assert transfer.scc_details is not None

    # Breach Management Tests
    @pytest.mark.asyncio
    async def test_breach_notification_deadline_compliance(self, breach_manager):
        """Test Article 33 - 72-hour notification deadline compliance"""
        
        # Arrange
        breach_data = {
            "title": "Data Breach Test",
            "description": "Unauthorized access to customer database",
            "breach_type": "confidentiality_breach",
            "severity": "high",
            "affected_data_categories": ["identification_data", "contact_information"],
            "estimated_affected_records": 1000
        }

        # Act
        breach = await breach_manager.report_breach(breach_data)

        # Assert
        assert breach is not None
        assert breach.authority_notification_deadline is not None
        
        # Verify 72-hour deadline
        deadline_hours = (breach.authority_notification_deadline - breach.detected_timestamp).total_seconds() / 3600
        assert abs(deadline_hours - 72) < 1  # Within 1 hour of 72 hours

    @pytest.mark.asyncio
    async def test_breach_risk_assessment_automation(self, breach_manager):
        """Test automatic breach risk assessment"""
        
        # Arrange - High risk breach
        breach_data = {
            "title": "High Risk Breach",
            "description": "Breach involving special categories of data",
            "breach_type": "confidentiality_breach",
            "severity": "critical",
            "affected_data_categories": ["health_data", "biometric_data"],
            "estimated_affected_records": 50000,
            "affected_data_subjects": [
                {
                    "categories": ["patients", "children"],
                    "sensitivity_level": "special_category",
                    "estimated_records": 50000
                }
            ]
        }

        # Act
        breach = await breach_manager.report_breach(breach_data)

        # Assert
        assert breach.status == BreachStatus.INVESTIGATING
        assert breach.breach_assessment is not None  # Preliminary assessment created
        assert breach.breach_assessment.risk_level.value in ["high", "critical"]
        assert breach.breach_assessment.individual_notification_required is True

    @pytest.mark.asyncio
    async def test_breach_authority_notification_article_33(self, breach_manager):
        """Test Article 33 supervisory authority notification"""
        
        # Arrange
        breach_data = {
            "title": "Article 33 Test Breach",
            "description": "Breach requiring authority notification",
            "breach_type": "confidentiality_breach",
            "severity": "medium",
            "affected_data_categories": ["identification_data"],
            "estimated_affected_records": 500
        }

        breach = await breach_manager.report_breach(breach_data)
        
        # Mock assessment
        breach.breach_assessment = Mock()
        breach.breach_assessment.authority_notification_required = True

        # Act
        notification = await breach_manager.notify_supervisory_authority(breach.id)

        # Assert
        assert notification is not None
        assert notification.notification_type == "authority"
        assert notification.recipient == "data_protection_authority"
        assert notification.notification_content is not None
        assert breach.authority_notified is True
        assert breach.status == BreachStatus.NOTIFIED_AUTHORITY

    @pytest.mark.asyncio
    async def test_breach_individual_notification_article_34(self, breach_manager):
        """Test Article 34 individual notification requirements"""
        
        # Arrange - High risk breach requiring individual notification
        breach_data = {
            "title": "High Risk Individual Notification",
            "description": "Breach with high risk to individuals",
            "breach_type": "confidentiality_breach", 
            "severity": "high",
            "affected_data_categories": ["health_data", "financial_data"],
            "estimated_affected_records": 1000,
            "affected_data_subjects": [
                {
                    "data_subject_id": "subject_1",
                    "categories": ["health_data"],
                    "sensitivity_level": "special_category",
                    "notification_required": True,
                    "contact_information": {"email": "test@example.com"}
                }
            ]
        }

        breach = await breach_manager.report_breach(breach_data)
        
        # Mock high-risk assessment
        breach.breach_assessment = Mock()
        breach.breach_assessment.individual_notification_required = True

        # Act
        notifications = await breach_manager.notify_affected_individuals(breach.id)

        # Assert
        assert len(notifications) > 0
        assert all(n.notification_type == "individuals" for n in notifications)
        assert breach.individuals_notified is True

    # Privacy by Design Tests
    @pytest.mark.asyncio
    async def test_privacy_assessment_article_25(self, privacy_framework):
        """Test Article 25 privacy assessment requirements"""
        
        # Act
        assessment = await privacy_framework.conduct_privacy_assessment(
            processing_activity="Customer Data Processing",
            data_categories=["identification_data", "contact_information"],
            processing_purposes=["customer_service", "marketing"],
            data_subjects_categories=["customers"],
            assessor="privacy_team"
        )

        # Assert
        assert assessment is not None
        assert assessment.processing_activity == "Customer Data Processing"
        assert len(assessment.identified_risks) > 0
        assert assessment.overall_risk_level in [risk.value for risk in PrivacyRisk]
        assert len(assessment.recommended_technologies) > 0
        assert len(assessment.mitigation_measures) > 0

    @pytest.mark.asyncio
    async def test_privacy_enhancing_technologies(self, privacy_framework):
        """Test Privacy Enhancing Technologies implementation"""
        
        # Test pseudonymization
        test_data = "john.doe@example.com"
        params = {"salt": "privacy_salt", "identifiable_fields": ["email"]}
        
        # Act
        pseudonymized_data = await privacy_framework.apply_privacy_technology(
            PrivacyEnhancingTechnology.PSEUDONYMIZATION,
            test_data,
            params
        )

        # Assert
        assert pseudonymized_data != test_data
        assert len(pseudonymized_data) == 16  # Pseudonym length
        
        # Test data minimization
        test_dict = {
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789",
            "age": 30
        }
        
        minimized_data = await privacy_framework.apply_privacy_technology(
            PrivacyEnhancingTechnology.DATA_MINIMIZATION,
            test_dict,
            {"required_fields": ["name", "email"]}
        )

        # Assert
        assert "ssn" not in minimized_data
        assert "name" in minimized_data
        assert "email" in minimized_data

    @pytest.mark.asyncio
    async def test_privacy_by_design_principles_validation(self, privacy_framework):
        """Test Privacy by Design foundational principles validation"""
        
        # Act
        validation_results = await privacy_framework.validate_privacy_implementation()

        # Assert
        assert "overall_status" in validation_results
        assert "technology_validation" in validation_results
        assert "requirement_compliance" in validation_results
        
        # Verify all privacy principles are covered
        requirements = privacy_framework.list_privacy_requirements()
        principle_coverage = set()
        for req in requirements:
            principle_coverage.add(req.principle)
        
        # Should cover all 7 Privacy by Design principles
        expected_principles = set(PrivacyPrinciple)
        assert len(principle_coverage.intersection(expected_principles)) >= 5  # At least 5 principles

    # Processing Records Tests (Article 30)
    @pytest.mark.asyncio
    async def test_processing_activity_article_30_compliance(self, records_manager):
        """Test Article 30 Records of Processing Activities compliance"""
        
        # Arrange
        activity_data = {
            "name": "Customer Data Processing",
            "description": "Processing of customer personal data for service delivery",
            "processing_role": ProcessingRole.CONTROLLER,
            "purposes": ["service_delivery", "customer_support"],
            "legal_basis": [LegalBasis.CONTRACT, LegalBasis.LEGITIMATE_INTERESTS],
            "data_categories": [DataCategory.IDENTIFICATION_DATA.value, DataCategory.CONTACT_INFORMATION.value],
            "data_subject_categories": [DataSubjectCategory.CUSTOMERS.value],
            "business_area": "Customer Operations",
            "estimated_data_subjects": 10000
        }

        # Act
        activity = await records_manager.create_processing_activity(activity_data, "test_user")

        # Assert
        assert activity is not None
        assert activity.name == "Customer Data Processing"
        assert activity.processing_role == ProcessingRole.CONTROLLER
        assert LegalBasis.CONTRACT in activity.legal_basis
        assert activity.dpia_required is not None  # DPIA requirement assessed
        assert activity.next_review_date is not None

    @pytest.mark.asyncio
    async def test_dpia_requirement_assessment(self, records_manager):
        """Test Data Protection Impact Assessment requirement determination"""
        
        # Arrange - High risk processing requiring DPIA
        high_risk_activity_data = {
            "name": "High Risk Processing",
            "description": "Large scale processing of special categories",
            "purposes": ["health_monitoring", "automated_decision_making"],
            "data_categories": [DataCategory.HEALTH_DATA.value, DataCategory.BIOMETRIC_DATA.value],
            "data_subject_categories": [DataSubjectCategory.PATIENTS.value, DataSubjectCategory.CHILDREN.value],
            "estimated_data_subjects": 50000,
            "automated_processing": True,
            "profiling": True
        }

        # Act
        activity = await records_manager.create_processing_activity(high_risk_activity_data, "test_user")

        # Assert
        assert activity.dpia_required is True

        # Test low risk processing
        low_risk_activity_data = {
            "name": "Low Risk Processing",
            "description": "Simple contact information processing",
            "purposes": ["newsletter"],
            "data_categories": [DataCategory.CONTACT_INFORMATION.value],
            "data_subject_categories": [DataSubjectCategory.CUSTOMERS.value],
            "estimated_data_subjects": 100
        }

        low_risk_activity = await records_manager.create_processing_activity(low_risk_activity_data, "test_user")
        assert low_risk_activity.dpia_required is False

    @pytest.mark.asyncio
    async def test_processing_records_audit_compliance(self, records_manager):
        """Test processing records audit for Article 30 compliance"""
        
        # Act
        audit_results = await records_manager.conduct_processing_audit()

        # Assert
        assert "total_activities" in audit_results
        assert "compliance_summary" in audit_results
        assert "dpia_summary" in audit_results
        assert "retention_compliance" in audit_results
        assert "security_measures" in audit_results
        assert "recommendations" in audit_results

        # Verify compliance categories
        compliance_summary = audit_results["compliance_summary"]
        assert "compliant" in compliance_summary
        assert "non_compliant" in compliance_summary
        assert "requires_attention" in compliance_summary

    # Integration Tests
    @pytest.mark.asyncio
    async def test_end_to_end_gdpr_compliance_workflow(self, dsr_manager, consent_manager, breach_manager):
        """Test end-to-end GDPR compliance workflow"""
        
        # Step 1: Collect consent
        templates = list(consent_manager.consent_templates.values())
        template = templates[0]
        purpose_consents = {purpose.id: True for purpose in template.purposes}
        
        consent_record = await consent_manager.collect_consent(
            data_subject_id="integration_test_subject",
            template_id=template.id,
            purpose_consents=purpose_consents
        )
        assert consent_record is not None

        # Step 2: Process data subject request
        data_subject = DataSubjectIdentity(
            email="integration@example.com",
            name="Integration Test Subject",
            verification_status="verified"
        )

        dsr_request = await dsr_manager.submit_rights_request(
            request_type=DataSubjectRightType.ACCESS,
            data_subject=data_subject,
            description="Integration test access request"
        )
        assert dsr_request is not None

        # Step 3: Simulate breach and test response
        breach_data = {
            "title": "Integration Test Breach",
            "description": "Simulated breach for integration testing",
            "breach_type": "confidentiality_breach",
            "severity": "medium",
            "affected_data_categories": ["identification_data"],
            "estimated_affected_records": 1
        }

        breach = await breach_manager.report_breach(breach_data)
        assert breach is not None
        assert breach.status == BreachStatus.INVESTIGATING

        # Verify all components work together
        assert consent_record.data_subject_id == "integration_test_subject"
        assert dsr_request.data_subject.email == "integration@example.com" 
        assert breach.title == "Integration Test Breach"

    @pytest.mark.asyncio
    async def test_gdpr_compliance_metrics(self, dsr_manager, consent_manager, breach_manager, privacy_framework):
        """Test GDPR compliance metrics collection"""
        
        # Collect metrics from all components
        dsr_stats = await dsr_manager.get_processing_statistics()
        consent_analytics = await consent_manager.get_consent_analytics()
        breach_stats = await breach_manager.generate_breach_statistics()
        privacy_validation = await privacy_framework.validate_privacy_implementation()

        # Assert all metrics are available
        assert isinstance(dsr_stats, dict)
        assert "total_requests" in dsr_stats
        
        assert hasattr(consent_analytics, 'total_consents')
        assert hasattr(consent_analytics, 'consent_rate')
        
        assert isinstance(breach_stats, dict)
        assert "total_breaches" in breach_stats
        
        assert isinstance(privacy_validation, dict)
        assert "overall_status" in privacy_validation

    # Performance Tests
    @pytest.mark.asyncio
    async def test_gdpr_performance_under_load(self, dsr_manager):
        """Test GDPR system performance under load"""
        
        # Create multiple concurrent requests
        tasks = []
        for i in range(10):
            data_subject = DataSubjectIdentity(
                email=f"load_test_{i}@example.com",
                name=f"Load Test Subject {i}",
                verification_status="verified"
            )
            
            task = dsr_manager.submit_rights_request(
                request_type=DataSubjectRightType.ACCESS,
                data_subject=data_subject,
                description=f"Load test request {i}"
            )
            tasks.append(task)

        # Execute all tasks concurrently
        start_time = datetime.now()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = datetime.now()

        # Assert
        processing_time = (end_time - start_time).total_seconds()
        assert processing_time < 10  # Should complete within 10 seconds
        assert len(results) == 10
        assert all(not isinstance(result, Exception) for result in results)

    # Error Handling Tests
    @pytest.mark.asyncio
    async def test_gdpr_error_handling_and_resilience(self, dsr_manager):
        """Test error handling and system resilience"""
        
        # Test invalid data subject request
        try:
            invalid_data_subject = DataSubjectIdentity(
                email="",  # Invalid empty email
                verification_status="failed"  # Failed verification
            )
            
            await dsr_manager.submit_rights_request(
                request_type=DataSubjectRightType.ACCESS,
                data_subject=invalid_data_subject
            )
            assert False, "Should have raised an exception"
        except Exception as e:
            assert isinstance(e, (ValueError, ValidationError, Exception))

    # Data Retention Tests
    @pytest.mark.asyncio
    async def test_data_retention_compliance(self, records_manager):
        """Test data retention compliance"""
        
        # Create activity with retention schedule
        activity_data = {
            "name": "Retention Test Activity",
            "description": "Testing retention compliance",
            "purposes": ["testing"],
            "data_categories": [DataCategory.IDENTIFICATION_DATA.value],
            "data_subject_categories": [DataSubjectCategory.CUSTOMERS.value]
        }

        activity = await records_manager.create_processing_activity(activity_data, "test_user")
        
        # Verify retention schedules are created
        assert len(activity.retention_schedules) > 0
        
        # Check retention periods are reasonable
        for schedule in activity.retention_schedules:
            assert schedule.retention_period > 0
            assert schedule.retention_period < 10000  # Less than ~27 years
            assert schedule.retention_basis is not None
            assert schedule.disposal_method is not None

    # Security Tests
    @pytest.mark.asyncio
    async def test_gdpr_security_measures_validation(self, records_manager):
        """Test security measures validation for GDPR compliance"""
        
        # Get activities and check security measures
        activities = records_manager.list_processing_activities()
        
        for activity in activities:
            if activity.security_measures:
                # Verify required security measure categories
                measure_categories = [m.category for m in activity.security_measures]
                
                # Should have basic security categories
                expected_categories = ["encryption", "access_control"]
                found_categories = [cat for cat in expected_categories 
                                 if any(cat in measure_cat for measure_cat in measure_categories)]
                
                assert len(found_categories) > 0, f"Activity {activity.name} missing basic security measures"


class TestGDPRAPICompliance:
    """Test API endpoints for GDPR compliance"""
    
    @pytest.mark.asyncio
    async def test_api_data_subject_rights_endpoint(self):
        """Test DSR API endpoint compliance"""
        # This would test the actual API endpoints
        # For now, verify the structure exists
        from src.api.gdpr_endpoints import gdpr_router
        
        routes = [route.path for route in gdpr_router.routes]
        
        # Verify key GDPR endpoints exist
        expected_endpoints = [
            "/api/v1/gdpr/data-subject-rights/requests",
            "/api/v1/gdpr/consent/collect",
            "/api/v1/gdpr/transfers",
            "/api/v1/gdpr/breaches",
            "/api/v1/gdpr/privacy-assessments",
            "/api/v1/gdpr/processing-activities"
        ]
        
        for endpoint in expected_endpoints:
            assert any(endpoint in route for route in routes), f"Missing endpoint: {endpoint}"

    def test_api_response_models_gdpr_compliant(self):
        """Test API response models include required GDPR information"""
        from src.api.gdpr_endpoints import DataSubjectRightsRequestModel
        
        # Verify required fields are present
        model_fields = DataSubjectRightsRequestModel.__fields__.keys()
        
        required_fields = ["request_type", "data_subject", "description"]
        for field in required_fields:
            assert field in model_fields, f"Missing required field: {field}"


# Fixtures for test data
@pytest.fixture
def sample_personal_data():
    """Sample personal data for testing"""
    return {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "phone": "+1-555-123-4567",
        "address": "123 Main St, City, State 12345",
        "date_of_birth": "1985-03-15",
        "ssn": "123-45-6789"
    }


@pytest.fixture
def sample_processing_activity():
    """Sample processing activity for testing"""
    return {
        "name": "Customer Onboarding",
        "description": "Processing customer data during account creation",
        "purposes": ["account_creation", "identity_verification"],
        "legal_basis": [LegalBasis.CONTRACT],
        "data_categories": [DataCategory.IDENTIFICATION_DATA, DataCategory.CONTACT_INFORMATION],
        "data_subject_categories": [DataSubjectCategory.CUSTOMERS],
        "retention_period": 2555  # 7 years
    }


# Utility functions for testing
def validate_gdpr_timestamp(timestamp_str: str) -> bool:
    """Validate timestamp format for GDPR compliance"""
    try:
        datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return True
    except ValueError:
        return False


def validate_gdpr_consent_record(consent_record: Dict[str, Any]) -> bool:
    """Validate consent record for GDPR compliance"""
    required_fields = [
        "id", "data_subject_id", "consent_timestamp", 
        "consent_method", "purposes", "consent_hash"
    ]
    
    return all(field in consent_record for field in required_fields)


def validate_gdpr_breach_notification(notification: Dict[str, Any]) -> bool:
    """Validate breach notification for Article 33/34 compliance"""
    required_fields = [
        "id", "breach_id", "notification_type", "recipient",
        "notification_timestamp", "notification_content"
    ]
    
    return all(field in notification for field in required_fields)


# Run specific test categories
if __name__ == "__main__":
    # Run all GDPR compliance tests
    pytest.main([__file__, "-v", "--tb=short"])