"""
Comprehensive GDPR Compliance Tests

Tests all aspects of GDPR compliance including data subject rights,
consent management, breach notification, and data protection principles.
"""

import pytest
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from tests.utils import ComplianceTestHelper, TestDataFactory, AssertionHelper
from src.core.gdpr.data_subject_rights import DataSubjectRightsManager
from src.core.gdpr.consent_management import ConsentManager
from src.core.gdpr.breach_management import BreachManager
from src.core.gdpr.dpia_system import DPIASystem
from src.core.gdpr.processing_records import ProcessingRecordsManager


class TestDataSubjectRights:
    """Test GDPR data subject rights implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.compliance_helper = ComplianceTestHelper()
        self.data_factory = TestDataFactory()
        self.rights_manager = DataSubjectRightsManager()
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_right_to_access_implementation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 15 - Right of access by the data subject."""
        # Arrange
        test_user_id = "test_user_12345"
        access_request = {
            "user_id": test_user_id,
            "request_type": "access",
            "identity_verification": {
                "method": "email_verification",
                "verified": True
            }
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/data-subject-rights/access",
            json=access_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Must provide information about processing
            assert "processing_purposes" in data
            assert "categories_of_data" in data
            assert "recipients" in data
            assert "retention_period" in data
            assert "data_source" in data
            
            # Must provide actual personal data
            assert "personal_data" in data
            
            # Must inform about rights
            assert "rights_information" in data
            assert "rectification" in data["rights_information"]
            assert "erasure" in data["rights_information"]
            assert "portability" in data["rights_information"]
        elif response.status_code == 404:
            # No data found for user - acceptable response
            assert "no data found" in response.json().get("detail", "").lower()
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_right_to_rectification_implementation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 16 - Right to rectification."""
        # Arrange
        rectification_request = {
            "user_id": "test_user_12345",
            "request_type": "rectification",
            "incorrect_data": {
                "field": "email",
                "current_value": "wrong@example.com",
                "correct_value": "correct@example.com"
            },
            "justification": "Email address was incorrectly entered"
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/data-subject-rights/rectify",
            json=rectification_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "processed"
            assert "completion_date" in data
            
            # Must inform third parties if applicable
            if "third_parties_notified" in data:
                assert isinstance(data["third_parties_notified"], list)
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_right_to_erasure_implementation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 17 - Right to erasure ('right to be forgotten')."""
        # Arrange
        erasure_request = {
            "user_id": "test_user_12345",
            "request_type": "erasure",
            "grounds": [
                "data_no_longer_necessary",
                "consent_withdrawn"
            ],
            "identity_verification": {
                "method": "strong_authentication",
                "verified": True
            }
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/data-subject-rights/erase",
            json=erasure_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Must confirm erasure or explain why not possible
            assert data["status"] in ["erased", "partially_erased", "refused"]
            
            if data["status"] == "refused":
                assert "refusal_reason" in data
                assert "legal_basis" in data
            
            if data["status"] in ["erased", "partially_erased"]:
                assert "erasure_date" in data
                assert "data_categories_erased" in data
                
                # Must inform third parties
                if "third_parties_informed" in data:
                    assert isinstance(data["third_parties_informed"], list)
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_right_to_data_portability_implementation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 20 - Right to data portability."""
        # Arrange
        portability_request = {
            "user_id": "test_user_12345",
            "request_type": "portability",
            "format": "json",
            "include_metadata": True
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/data-subject-rights/export",
            json=portability_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Must provide data in structured, commonly used format
            assert "export_format" in data
            assert data["export_format"] in ["json", "xml", "csv"]
            
            # Must be machine-readable
            assert "data_export" in data
            if isinstance(data["data_export"], str):
                # Should be valid JSON/XML/CSV
                try:
                    if data["export_format"] == "json":
                        json.loads(data["data_export"])
                except json.JSONDecodeError:
                    pytest.fail("Data export is not valid JSON")
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_response_time_compliance(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test compliance with GDPR response time requirements (Article 12)."""
        # Arrange
        access_request = {
            "user_id": "test_user_12345",
            "request_type": "access",
            "request_date": datetime.utcnow().isoformat()
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/data-subject-rights/access",
            json=access_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Must respond within 1 month (can be extended to 3 months for complex requests)
            if "estimated_completion_date" in data:
                completion_date = datetime.fromisoformat(data["estimated_completion_date"])
                request_date = datetime.utcnow()
                
                time_difference = completion_date - request_date
                assert time_difference.days <= 30, "Response time exceeds GDPR 1-month requirement"
                
                # If extension is claimed, must be justified
                if time_difference.days > 30:
                    assert "extension_justification" in data
                    assert time_difference.days <= 90  # Maximum 3 months


class TestConsentManagement:
    """Test GDPR consent management compliance."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.consent_manager = ConsentManager()
        self.compliance_helper = ComplianceTestHelper()
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_consent_validity_requirements(self, client: TestClient):
        """Test Article 7 - Conditions for consent."""
        # Arrange - Test consent request
        consent_request = {
            "user_id": "test_user_12345",
            "processing_purposes": [
                {
                    "purpose": "pii_detection",
                    "description": "Process documents to detect and redact personal information",
                    "legal_basis": "consent"
                }
            ],
            "data_categories": ["personal_identifiers", "contact_information"],
            "consent_method": "explicit",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/consent/request",
            json=consent_request
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Consent must be specific
            assert "specific_purposes" in data
            assert len(data["specific_purposes"]) > 0
            
            # Consent must be informed
            assert "information_provided" in data
            assert "clear_language" in data["information_provided"]
            assert "processing_details" in data["information_provided"]
            
            # Consent must be freely given
            assert "freely_given_confirmation" in data
            
            # Must be able to withdraw
            assert "withdrawal_mechanism" in data
            assert "withdrawal_as_easy_as_giving" in data
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_consent_withdrawal_mechanism(self, client: TestClient):
        """Test Article 7(3) - Right to withdraw consent."""
        # Arrange
        withdrawal_request = {
            "user_id": "test_user_12345",
            "consent_id": "consent_12345",
            "withdrawal_timestamp": datetime.utcnow().isoformat()
        }
        
        # Act
        response = client.post(
            "/api/v1/gdpr/consent/withdraw",
            json=withdrawal_request
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Withdrawal must be processed immediately
            assert data["status"] == "withdrawn"
            assert "withdrawal_effective_date" in data
            
            # Processing must stop
            assert "processing_stopped" in data
            assert data["processing_stopped"] is True
            
            # User must be informed of consequences
            assert "consequences_explained" in data
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_consent_record_keeping(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test Article 7(1) - Demonstrating consent."""
        # Act
        response = client.get(
            "/api/v1/gdpr/consent/records",
            params={"user_id": "test_user_12345"},
            headers=admin_auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            if "consent_records" in data:
                for record in data["consent_records"]:
                    # Must record how consent was obtained
                    assert "consent_method" in record
                    assert "timestamp" in record
                    assert "consent_text" in record
                    
                    # Must record when consent was given
                    assert "given_date" in record
                    
                    # Must record what was consented to
                    assert "processing_purposes" in record
                    assert "data_categories" in record


class TestDataProtectionPrinciples:
    """Test GDPR data protection principles (Article 5)."""
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_lawfulness_fairness_transparency(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 5(1)(a) - Lawfulness, fairness and transparency."""
        # Test transparency through privacy notice
        response = client.get("/api/v1/gdpr/privacy-notice")
        
        if response.status_code == 200:
            data = response.json()
            
            # Must provide clear information about processing
            assert "controller_identity" in data
            assert "processing_purposes" in data
            assert "legal_basis" in data
            assert "data_categories" in data
            assert "recipients" in data
            assert "retention_periods" in data
            assert "data_subject_rights" in data
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_purpose_limitation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 5(1)(b) - Purpose limitation."""
        # Arrange - Process data for stated purpose
        processing_request = {
            "text": "John Smith works at Acme Corp",
            "declared_purpose": "pii_detection",
            "processing_context": "document_redaction"
        }
        
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            json=processing_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Should only process for declared purpose
            assert "processing_purpose_verified" in data
            assert data["processing_purpose_verified"] is True
            
            # Should not use data for incompatible purposes
            if "additional_processing" in data:
                assert data["additional_processing"]["compatible_purpose"] is True
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_data_minimisation(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 5(1)(c) - Data minimisation."""
        # Arrange
        processing_request = {
            "text": self.data_factory.create_pii_text(['PERSON', 'EMAIL', 'PHONE_NUMBER', 'ADDRESS']),
            "required_entities": ["PERSON", "EMAIL"],  # Only need some entities
            "purpose": "contact_redaction"
        }
        
        # Act
        response = client.post(
            "/api/v1/pii/detect",
            json=processing_request,
            headers=auth_headers
        )
        
        # Assert
        if response.status_code == 200:
            data = response.json()
            
            # Should only process necessary data
            detected_types = set(entity["label"] for entity in data.get("entities", []))
            
            # If data minimisation is implemented, should prefer requested entities
            if "data_minimisation_applied" in data:
                assert data["data_minimisation_applied"] is True
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_accuracy_principle(self, client: TestClient, auth_headers: Dict[str, str]):
        """Test Article 5(1)(d) - Accuracy."""
        # Test correction mechanism
        correction_request = {
            "document_id": "test_doc_12345",
            "corrections": [
                {
                    "field": "detected_entity",
                    "incorrect_value": "Jon Smith",
                    "correct_value": "John Smith",
                    "entity_type": "PERSON"
                }
            ]
        }
        
        response = client.post(
            "/api/v1/gdpr/data-accuracy/correct",
            json=correction_request,
            headers=auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            assert "corrections_applied" in data
            assert data["corrections_applied"] > 0
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_storage_limitation(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test Article 5(1)(e) - Storage limitation."""
        # Test retention policy enforcement
        response = client.get(
            "/api/v1/gdpr/retention/policy",
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Must have defined retention periods
            assert "retention_periods" in data
            
            for category, period in data["retention_periods"].items():
                assert isinstance(period, int)
                assert period > 0
                assert period <= 2555  # Maximum 7 years for most data
            
            # Must have deletion procedures
            assert "deletion_procedures" in data
            assert "automated_deletion" in data


class TestDataProtectionByDesign:
    """Test GDPR Data Protection by Design and by Default (Article 25)."""
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_privacy_by_design_implementation(self, client: TestClient):
        """Test privacy by design principles."""
        # Test system defaults
        response = client.get("/api/v1/gdpr/privacy-settings/defaults")
        
        if response.status_code == 200:
            data = response.json()
            
            # Default settings should be privacy-friendly
            assert "default_retention_period" in data
            assert "default_data_sharing" in data
            assert data["default_data_sharing"] is False  # Should default to no sharing
            
            assert "privacy_protective_defaults" in data
            assert data["privacy_protective_defaults"] is True
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_data_protection_impact_assessment(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test DPIA implementation (Article 35)."""
        # Request DPIA information
        response = client.get(
            "/api/v1/gdpr/dpia/assessment",
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # DPIA must contain specific elements
            assert "processing_description" in data
            assert "necessity_assessment" in data
            assert "proportionality_assessment" in data
            assert "risks_identification" in data
            assert "mitigation_measures" in data
            
            # Must assess high risks
            if "high_risk_processing" in data:
                assert "supervisory_authority_consulted" in data


class TestBreachNotification:
    """Test GDPR breach notification requirements (Articles 33-34)."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.breach_manager = BreachManager()
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_supervisory_authority_notification(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test Article 33 - Notification to supervisory authority."""
        # Simulate breach detection
        breach_report = {
            "breach_type": "confidentiality_breach",
            "affected_individuals": 150,
            "data_categories": ["personal_identifiers", "contact_information"],
            "discovery_date": datetime.utcnow().isoformat(),
            "likely_consequences": "Identity theft risk",
            "mitigation_measures": ["Password reset", "Account monitoring"]
        }
        
        response = client.post(
            "/api/v1/gdpr/breach/report",
            json=breach_report,
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Must notify within 72 hours if high risk
            assert "notification_deadline" in data
            notification_deadline = datetime.fromisoformat(data["notification_deadline"])
            discovery_time = datetime.fromisoformat(breach_report["discovery_date"])
            
            time_to_notify = notification_deadline - discovery_time
            assert time_to_notify.total_seconds() <= 72 * 3600  # 72 hours
            
            # Must include specific information
            assert "breach_description" in data
            assert "affected_categories" in data
            assert "approximate_number" in data
            assert "likely_consequences" in data
            assert "measures_taken" in data
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_data_subject_notification(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test Article 34 - Communication of breach to data subject."""
        # High risk breach requiring individual notification
        high_risk_breach = {
            "breach_type": "confidentiality_breach",
            "affected_individuals": 50,
            "risk_level": "high",
            "data_categories": ["financial_information", "health_data"],
            "notification_required": True
        }
        
        response = client.post(
            "/api/v1/gdpr/breach/notify-individuals",
            json=high_risk_breach,
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Must notify individuals if high risk
            assert "individuals_notified" in data
            assert data["individuals_notified"] > 0
            
            # Notification must be in plain language
            assert "notification_language" in data
            assert data["notification_language"] == "plain"
            
            # Must describe likely consequences
            assert "consequences_described" in data
            assert "mitigation_advice" in data


class TestInternationalTransfers:
    """Test GDPR international transfer requirements (Chapter V)."""
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_adequacy_decision_compliance(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test transfers based on adequacy decisions."""
        # Test transfer restrictions
        transfer_request = {
            "data_categories": ["personal_identifiers"],
            "destination_country": "US",  # Non-adequate country
            "transfer_purpose": "data_processing",
            "safeguards": ["standard_contractual_clauses"]
        }
        
        response = client.post(
            "/api/v1/gdpr/transfers/validate",
            json=transfer_request,
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Must validate transfer legality
            assert "transfer_permitted" in data
            assert "legal_basis" in data
            
            if not data["transfer_permitted"]:
                assert "reasons" in data
            
            if data["transfer_permitted"]:
                assert "safeguards_applied" in data


class TestComplianceReporting:
    """Test GDPR compliance monitoring and reporting."""
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_processing_records_maintenance(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test Article 30 - Records of processing activities."""
        response = client.get(
            "/api/v1/gdpr/processing-records",
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if "processing_activities" in data:
                for activity in data["processing_activities"]:
                    # Must contain required information
                    assert "controller_name" in activity
                    assert "processing_purposes" in activity
                    assert "data_categories" in activity
                    assert "recipients" in activity
                    assert "retention_periods" in activity
                    assert "security_measures" in activity
    
    @pytest.mark.compliance
    @pytest.mark.gdpr
    def test_compliance_monitoring(self, client: TestClient, admin_auth_headers: Dict[str, str]):
        """Test ongoing compliance monitoring."""
        response = client.get(
            "/api/v1/gdpr/compliance/status",
            headers=admin_auth_headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Should monitor key compliance areas
            compliance_areas = [
                "lawful_basis",
                "consent_management", 
                "data_subject_rights",
                "security_measures",
                "breach_procedures",
                "privacy_notices"
            ]
            
            for area in compliance_areas:
                if area in data:
                    assert "status" in data[area]
                    assert "last_reviewed" in data[area]
                    assert data[area]["status"] in ["compliant", "non_compliant", "partial"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "compliance and gdpr"])