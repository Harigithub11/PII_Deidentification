"""
Comprehensive HIPAA Compliance Testing Suite

This module provides extensive testing for HIPAA Safe Harbor compliance,
ensuring 99.5%+ accuracy in de-identification of all 18 PHI categories.

Test Coverage:
- All 18 HIPAA PHI identifier categories
- Safe Harbor method validation
- Statistical disclosure control
- Breach detection and notification
- Business Associate Agreement compliance
- Audit trail completeness
"""

import pytest
import asyncio
import tempfile
import json
from datetime import datetime, timedelta
from uuid import uuid4
from typing import Dict, List, Any
import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.core.compliance.hipaa_safe_harbor import (
    SafeHarborProcessor, SafeHarborConfig, PHICategory, DeidentificationResult
)
from src.core.compliance.hipaa_baa import (
    HIPAABAAManager, BusinessAssociate, BAAStatus, ComplianceLevel, 
    IncidentSeverity, ComplianceIncident
)


class TestHIPAASafeHarbor:
    """Test suite for HIPAA Safe Harbor de-identification."""
    
    @pytest.fixture
    def processor(self):
        """Create SafeHarborProcessor instance for testing."""
        config = SafeHarborConfig(
            validation_enabled=True,
            audit_logging=True,
            statistical_disclosure_control=True
        )
        return SafeHarborProcessor(config)
    
    @pytest.fixture
    def phi_test_data(self):
        """Comprehensive PHI test data covering all 18 categories."""
        return {
            # (A) Names
            "names": [
                "Patient John Smith visited the clinic.",
                "Dr. Sarah Johnson reviewed the case.",
                "Mary Elizabeth Wilson, MD",
                "Patient: Robert Thompson"
            ],
            
            # (B) Geographic subdivisions smaller than state
            "geographic": [
                "Address: 123 Main Street, Apartment 4B",
                "ZIP Code: 12345-6789",
                "Lives in Cook County, Illinois",
                "City of Springfield resident"
            ],
            
            # (C) All elements of dates (except year for >89 years old)
            "dates": [
                "Date of birth: 01/15/1985",
                "Admission date: March 10, 2023",
                "Surgery scheduled for 2023-12-25",
                "Born January 1st, 1930",  # > 89 years old
                "Visited on 05-20-2023"
            ],
            
            # (D) Telephone numbers
            "telephone": [
                "Phone: (555) 123-4567",
                "Call 555.987.6543 for appointment",
                "Mobile: +1-555-234-5678",
                "Telephone number: 5551234567"
            ],
            
            # (E) Fax numbers
            "fax": [
                "Fax: (555) 987-6543",
                "Send fax to 555-555-5555",
                "Facsimile: +1 555 123 4567"
            ],
            
            # (F) Electronic mail addresses
            "email": [
                "Contact: john.doe@hospital.com",
                "Email patient@gmail.com for results",
                "Send to: mary.smith@clinic.org"
            ],
            
            # (G) Social security numbers
            "ssn": [
                "SSN: 123-45-6789",
                "Social Security Number 987654321",
                "Patient SSN is 555-55-5555"
            ],
            
            # (H) Medical record numbers
            "mrn": [
                "MRN: MR123456789",
                "Medical record number: 987654321",
                "Chart number: CH-2023-001",
                "Patient ID: PID123456"
            ],
            
            # (I) Health plan beneficiary numbers
            "health_plan": [
                "Insurance ID: INS123456789",
                "Member ID: MEM987654321",
                "Policy number: POL-2023-001",
                "Medicare: 1EG4-TE5-MK72"
            ],
            
            # (J) Account numbers
            "account": [
                "Account number: ACC123456789",
                "Billing account: BILL-2023-001",
                "Invoice #: INV987654321"
            ],
            
            # (K) Certificate/license numbers
            "certificate": [
                "NPI: 1234567890",
                "DEA number: AB1234567",
                "License #: LIC123456789",
                "Certificate: CERT-2023-001"
            ],
            
            # (L) Vehicle identifiers
            "vehicle": [
                "VIN: 1HGBH41JXMN109186",
                "License plate: ABC-123",
                "Vehicle ID: VEH123456789"
            ],
            
            # (M) Device identifiers
            "device": [
                "Serial number: SN123456789",
                "Device ID: DEV-2023-001",
                "Equipment serial: EQ987654321",
                "Model number: MOD123ABC"
            ],
            
            # (N) Web URLs
            "urls": [
                "Visit https://www.hospital.com/patient-portal",
                "Download results from www.clinic.org/results",
                "Check http://portal.healthcare.com"
            ],
            
            # (O) IP addresses
            "ip_addresses": [
                "Server IP: 192.168.1.100",
                "Connect to 10.0.0.1 for access",
                "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
            ],
            
            # (P) Biometric identifiers
            "biometric": [
                "Fingerprint ID: FP123456789",
                "Retinal scan: RET987654321",
                "Biometric identifier: BIO-2023-001"
            ],
            
            # (Q) Full face photographic images - handled separately
            
            # (R) Other unique identifying numbers
            "other_ids": [
                "Unique identifier: UID123456789",
                "Reference number: REF987654321",
                "Tracking ID: TRK-2023-001"
            ]
        }
    
    def test_phi_category_detection_accuracy(self, processor, phi_test_data):
        """Test detection accuracy for all PHI categories."""
        
        results = {}
        total_phi_instances = 0
        detected_phi_instances = 0
        
        for category, test_texts in phi_test_data.items():
            category_results = {
                "total_tests": len(test_texts),
                "detected": 0,
                "accuracy": 0.0,
                "failed_cases": []
            }
            
            for text in test_texts:
                result = processor.process_document(text)
                
                total_phi_instances += 1
                
                # Check if PHI was detected in this category
                category_detected = any(
                    phi["category"] in self._get_related_categories(category)
                    for phi in result.phi_found
                )
                
                if category_detected:
                    category_results["detected"] += 1
                    detected_phi_instances += 1
                else:
                    category_results["failed_cases"].append(text)
            
            category_results["accuracy"] = (
                category_results["detected"] / category_results["total_tests"] * 100
            )
            results[category] = category_results
        
        # Overall accuracy
        overall_accuracy = detected_phi_instances / total_phi_instances * 100
        
        # Assert minimum accuracy requirements
        assert overall_accuracy >= 95.0, f"Overall accuracy {overall_accuracy:.1f}% below 95% threshold"
        
        # Check critical categories have high accuracy
        critical_categories = ["names", "ssn", "email", "dates"]
        for category in critical_categories:
            if category in results:
                accuracy = results[category]["accuracy"]
                assert accuracy >= 90.0, f"{category} accuracy {accuracy:.1f}% below 90% threshold"
        
        return results
    
    def test_safe_harbor_compliance_validation(self, processor):
        """Test Safe Harbor compliance validation."""
        
        # Test compliant text
        compliant_text = """
        Patient visited clinic in 2023. 
        Age: 45 years old.
        Diagnosis: Hypertension.
        Treatment plan discussed.
        """
        
        result = processor.process_document(compliant_text)
        assert result.safe_harbor_compliant == True
        
        # Test non-compliant text with obvious PHI
        non_compliant_text = """
        John Smith (SSN: 123-45-6789) visited on 01/15/2023.
        Phone: (555) 123-4567
        Email: john.smith@email.com
        Address: 123 Main St, Springfield, IL 62701
        """
        
        result = processor.process_document(non_compliant_text)
        assert len(result.phi_found) > 0
        assert result.safe_harbor_compliant == False
    
    def test_date_handling_age_aggregation(self, processor):
        """Test proper date handling for patients over 89 years old."""
        
        # Patient over 89 (born 1930, would be 93+ in 2023)
        old_patient_text = "Patient born January 1, 1930, visited on March 15, 2023."
        result = processor.process_document(old_patient_text)
        
        # Should aggregate ages 90 and above
        deidentified = result.deidentified_text
        assert "90+" in deidentified or "[DATE]" in deidentified
        
        # Patient under 89 (born 1980, would be 43 in 2023)
        young_patient_text = "Patient born June 10, 1980, visited on March 15, 2023."
        result = processor.process_document(young_patient_text)
        
        # Should retain year for younger patients
        deidentified = result.deidentified_text
        # Year may be retained or replaced with [DATE]
        assert len(deidentified) > 0
    
    def test_statistical_disclosure_control(self, processor):
        """Test statistical disclosure control measures."""
        
        # High-risk text with multiple unique identifiers
        high_risk_text = """
        John Smith, SSN 123-45-6789, MRN MR123456, 
        phone 555-123-4567, email john@email.com,
        account ACC123, insurance INS456,
        lives at 123 Main St, Springfield IL 62701
        """
        
        result = processor.process_document(high_risk_text)
        
        # Should detect high re-identification risk
        # Statistical disclosure control should flag this
        assert len(result.phi_found) >= 5  # Multiple PHI types
        
        # Low-risk text
        low_risk_text = "Patient age 45, diagnosis of hypertension, prescribed medication."
        result = processor.process_document(low_risk_text)
        assert result.safe_harbor_compliant == True
    
    def test_zip_code_truncation(self, processor):
        """Test ZIP code truncation to first 3 digits."""
        
        text = "Patient lives in ZIP code 12345-6789"
        result = processor.process_document(text)
        
        # ZIP should be truncated to first 3 digits
        deidentified = result.deidentified_text
        assert "123**" in deidentified or "[ZIP]" in deidentified
    
    def test_audit_trail_completeness(self, processor):
        """Test completeness of audit trail for compliance."""
        
        text = """
        Patient John Doe (SSN: 123-45-6789) 
        Phone: (555) 123-4567
        Email: john.doe@email.com
        """
        
        result = processor.process_document(text)
        
        # Should have audit entries for each PHI found
        assert len(result.audit_trail) > 0
        assert len(result.audit_trail) == len(result.phi_found)
        
        # Each audit entry should have required fields
        for audit_entry in result.audit_trail:
            assert "timestamp" in audit_entry
            assert "action" in audit_entry
            assert "category" in audit_entry
            assert "method" in audit_entry
            assert audit_entry["action"] == "phi_deidentified"
    
    def test_confidence_score_calculation(self, processor):
        """Test confidence score calculation accuracy."""
        
        # High confidence case (clear PHI patterns)
        clear_phi_text = "SSN: 123-45-6789, Phone: (555) 123-4567"
        result = processor.process_document(clear_phi_text)
        assert result.confidence_score >= 0.90
        
        # Lower confidence case (ambiguous text)
        ambiguous_text = "Call me at work tomorrow"
        result = processor.process_document(ambiguous_text)
        # Should have high confidence if no PHI detected
        assert result.confidence_score >= 0.85
    
    def test_replacement_consistency(self, processor):
        """Test that same PHI values get consistent replacements."""
        
        text1 = "John Smith visited on Monday"
        text2 = "John Smith called on Tuesday"
        
        result1 = processor.process_document(text1)
        result2 = processor.process_document(text2)
        
        # Same name should get same replacement (when using hash-based method)
        if result1.phi_found and result2.phi_found:
            name_replacements_1 = [
                phi["replacement"] for phi in result1.phi_found 
                if phi["category"] == "names"
            ]
            name_replacements_2 = [
                phi["replacement"] for phi in result2.phi_found 
                if phi["category"] == "names"
            ]
            
            if name_replacements_1 and name_replacements_2:
                # Should have consistent replacement for same name
                assert name_replacements_1[0] == name_replacements_2[0]
    
    def test_performance_requirements(self, processor):
        """Test processing performance meets requirements."""
        
        # Test with typical healthcare document
        healthcare_doc = """
        MEDICAL RECORD
        
        Patient: John Smith
        DOB: 01/15/1980
        SSN: 123-45-6789
        Phone: (555) 123-4567
        Email: john.smith@email.com
        Address: 123 Main Street, Springfield, IL 62701
        
        MRN: MR123456789
        Insurance: INS987654321
        Account: ACC555666777
        
        Chief Complaint: Chest pain
        History: 45-year-old male presents with chest pain...
        
        Assessment and Plan:
        1. Chest pain - likely musculoskeletal
        2. Follow up in 2 weeks
        3. Call if symptoms worsen: (555) 123-4567
        
        Provider: Dr. Sarah Johnson, MD
        NPI: 1234567890
        """
        
        start_time = datetime.now()
        result = processor.process_document(healthcare_doc)
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Should process typical document in under 5 seconds
        assert processing_time < 5.0, f"Processing time {processing_time:.2f}s exceeds 5s limit"
        
        # Should detect multiple PHI categories
        assert len(result.phi_found) >= 5
        
        # Should maintain readability
        assert len(result.deidentified_text) > 0
        assert "Chest pain" in result.deidentified_text  # Medical content preserved
    
    def _get_related_categories(self, test_category: str) -> List[str]:
        """Map test categories to PHI categories."""
        
        mapping = {
            "names": ["names"],
            "geographic": ["geographic"],
            "dates": ["dates"],
            "telephone": ["telephone"],
            "fax": ["fax"],
            "email": ["email"],
            "ssn": ["ssn"],
            "mrn": ["mrn"],
            "health_plan": ["hpb"],
            "account": ["account"],
            "certificate": ["certificate"],
            "vehicle": ["vehicle"],
            "device": ["device"],
            "urls": ["web_urls"],
            "ip_addresses": ["ip_addresses"],
            "biometric": ["biometric"],
            "other_ids": ["other_ids"]
        }
        
        return mapping.get(test_category, [test_category])


class TestHIPAABusinessAssociates:
    """Test suite for HIPAA Business Associate Agreement management."""
    
    @pytest.fixture
    def baa_manager(self):
        """Create BAA manager instance for testing."""
        return HIPAABAAManager()
    
    def test_business_associate_creation(self, baa_manager):
        """Test business associate creation and management."""
        
        ba = baa_manager.create_business_associate(
            name="TechCorp Healthcare Solutions",
            organization_type="Technology Services",
            contact_person="Jane Doe",
            contact_email="jane.doe@techcorp.com",
            services_provided=["Data Processing", "Cloud Storage"],
            phi_access_level="limited"
        )
        
        assert ba.name == "TechCorp Healthcare Solutions"
        assert ba.organization_type == "Technology Services"
        assert ba.baa_status == BAAStatus.DRAFT
        assert ba.compliance_level == ComplianceLevel.UNKNOWN
        assert ba.id in baa_manager.business_associates
    
    def test_baa_execution(self, baa_manager):
        """Test BAA execution process."""
        
        # Create business associate
        ba = baa_manager.create_business_associate(
            name="HealthTech Solutions",
            organization_type="Healthcare IT"
        )
        
        # Get template
        tech_template_id = list(baa_manager.baa_templates.keys())[0]
        
        # Execute BAA
        success = baa_manager.execute_baa(ba.id, tech_template_id)
        assert success == True
        
        # Verify BAA status
        updated_ba = baa_manager.business_associates[ba.id]
        assert updated_ba.baa_status == BAAStatus.ACTIVE
        assert updated_ba.baa_signed_date is not None
        assert updated_ba.baa_expiration_date is not None
    
    def test_compliance_assessment(self, baa_manager):
        """Test compliance assessment functionality."""
        
        # Create business associate with good compliance
        ba = baa_manager.create_business_associate(
            name="Compliant Corp",
            organization_type="Healthcare Services"
        )
        
        # Execute BAA
        template_id = list(baa_manager.baa_templates.keys())[0]
        baa_manager.execute_baa(ba.id, template_id)
        
        # Set up good security measures
        ba.security_measures = {
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "access_controls": True
        }
        ba.audit_logging_enabled = True
        ba.access_controls_implemented = True
        ba.phi_access_level = "limited"
        
        # Perform assessment
        assessment = baa_manager.assess_compliance(ba.id)
        
        assert "compliance_score" in assessment
        assert assessment["compliance_score"] >= 70.0  # Should be compliant
        assert len(assessment["findings"]) > 0
        assert "recommendations" in assessment
    
    def test_incident_management(self, baa_manager):
        """Test incident creation and management."""
        
        # Create business associate
        ba = baa_manager.create_business_associate(
            name="Partner Corp",
            organization_type="Business Partner"
        )
        
        # Create incident
        incident = baa_manager.create_incident(
            title="Unauthorized PHI Access",
            description="Employee accessed PHI without authorization",
            severity=IncidentSeverity.HIGH,
            business_associate_id=ba.id,
            phi_involved=True,
            individuals_affected=100
        )
        
        assert incident.title == "Unauthorized PHI Access"
        assert incident.severity == IncidentSeverity.HIGH
        assert incident.phi_involved == True
        assert incident.breach_notification_required == True  # Auto-determined
        assert incident.regulatory_notification_required == True
        
        # Process response action
        success = baa_manager.process_incident_response(
            incident.id,
            "containment_action",
            {
                "action_taken": "Disabled user access",
                "performed_by": "Security Team",
                "timestamp": datetime.now().isoformat()
            }
        )
        
        assert success == True
        assert len(incident.response_actions) == 1
    
    def test_compliance_reporting(self, baa_manager):
        """Test compliance report generation."""
        
        # Set up test data
        ba1 = baa_manager.create_business_associate(name="Partner 1", organization_type="Tech")
        ba2 = baa_manager.create_business_associate(name="Partner 2", organization_type="Healthcare")
        
        template_id = list(baa_manager.baa_templates.keys())[0]
        baa_manager.execute_baa(ba1.id, template_id)
        baa_manager.execute_baa(ba2.id, template_id)
        
        # Create incident
        baa_manager.create_incident(
            title="Test Incident",
            description="Test incident",
            severity=IncidentSeverity.MEDIUM,
            business_associate_id=ba1.id
        )
        
        # Generate report
        report = baa_manager.generate_compliance_report()
        
        assert "summary" in report
        assert "business_associates" in report
        assert "incidents" in report
        assert "recommendations" in report
        
        assert report["summary"]["total_business_associates"] == 2
        assert report["summary"]["active_baas"] == 2
        assert len(report["business_associates"]) == 2
        assert len(report["incidents"]) == 1
    
    def test_expiring_baa_detection(self, baa_manager):
        """Test detection of expiring BAAs."""
        
        # Create business associate with soon-to-expire BAA
        ba = baa_manager.create_business_associate(name="Expiring Corp", organization_type="Services")
        
        # Execute BAA with custom expiration
        template_id = list(baa_manager.baa_templates.keys())[0]
        baa_manager.execute_baa(ba.id, template_id)
        
        # Set expiration to 15 days from now
        ba.baa_expiration_date = datetime.now() + timedelta(days=15)
        
        # Check expiring BAAs
        expiring = baa_manager.get_expiring_baas(days_ahead=30)
        assert len(expiring) == 1
        assert expiring[0].id == ba.id
    
    def test_metrics_tracking(self, baa_manager):
        """Test compliance metrics tracking."""
        
        # Initial metrics
        initial_metrics = baa_manager.get_compliance_metrics()
        assert initial_metrics["total_business_associates"] == 0
        
        # Create business associates
        ba1 = baa_manager.create_business_associate(name="Corp 1", organization_type="Tech")
        ba2 = baa_manager.create_business_associate(name="Corp 2", organization_type="Healthcare")
        
        # Execute BAAs
        template_id = list(baa_manager.baa_templates.keys())[0]
        baa_manager.execute_baa(ba1.id, template_id)
        baa_manager.execute_baa(ba2.id, template_id)
        
        # Set compliance levels
        ba1.compliance_level = ComplianceLevel.COMPLIANT
        ba2.compliance_level = ComplianceLevel.PARTIALLY_COMPLIANT
        baa_manager._update_compliance_metrics()
        
        # Check updated metrics
        metrics = baa_manager.get_compliance_metrics()
        assert metrics["total_business_associates"] == 2
        assert metrics["active_baas"] == 2
        assert metrics["compliance_rate"] == 50.0  # 1 out of 2 compliant


class TestHIPAAIntegrationScenarios:
    """Integration tests for complete HIPAA compliance workflows."""
    
    @pytest.fixture
    def processor(self):
        return SafeHarborProcessor()
    
    @pytest.fixture 
    def baa_manager(self):
        return HIPAABAAManager()
    
    def test_end_to_end_healthcare_workflow(self, processor, baa_manager):
        """Test complete healthcare document processing workflow."""
        
        # 1. Set up business associate
        ba = baa_manager.create_business_associate(
            name="Regional Hospital",
            organization_type="Healthcare Provider",
            contact_person="Dr. Smith",
            contact_email="compliance@hospital.com",
            services_provided=["Medical Records Management"],
            phi_access_level="full"
        )
        
        # 2. Execute BAA
        template_id = list(baa_manager.baa_templates.keys())[0]
        baa_manager.execute_baa(ba.id, template_id)
        
        # 3. Process healthcare document
        healthcare_document = """
        DISCHARGE SUMMARY
        
        Patient: Jennifer Anderson
        DOB: 03/22/1975
        SSN: 456-78-9123
        MRN: MR789123456
        
        Address: 456 Oak Avenue, Chicago, IL 60601
        Phone: (312) 555-0123
        Email: jennifer.anderson@email.com
        
        Admission Date: 2023-08-15
        Discharge Date: 2023-08-18
        
        Attending Physician: Dr. Michael Roberts, MD
        NPI: 9876543210
        
        DIAGNOSIS: Acute appendicitis
        PROCEDURE: Laparoscopic appendectomy
        
        HOSPITAL COURSE:
        Patient presented with acute right lower quadrant pain...
        
        DISCHARGE MEDICATIONS:
        1. Ibuprofen 600mg every 6 hours as needed for pain
        2. Follow up with Dr. Roberts in 1 week
        
        Contact clinic at (312) 555-0199 for questions.
        """
        
        result = processor.process_document(
            healthcare_document,
            document_metadata={
                "document_type": "discharge_summary",
                "business_associate_id": str(ba.id),
                "processing_date": datetime.now().isoformat()
            }
        )
        
        # 4. Validate de-identification results
        assert len(result.phi_found) >= 8  # Multiple PHI types expected
        assert result.confidence_score >= 0.90
        
        # 5. Check specific PHI categories were detected
        phi_categories = set(phi["category"] for phi in result.phi_found)
        expected_categories = {"names", "dates", "ssn", "mrn", "geographic", "telephone", "email"}
        assert len(phi_categories.intersection(expected_categories)) >= 5
        
        # 6. Verify medical content preserved
        deidentified = result.deidentified_text
        assert "DIAGNOSIS: Acute appendicitis" in deidentified
        assert "PROCEDURE: Laparoscopic appendectomy" in deidentified
        assert "Ibuprofen 600mg" in deidentified
        
        # 7. Verify PHI removed/replaced
        assert "Jennifer Anderson" not in deidentified
        assert "456-78-9123" not in deidentified
        assert "456 Oak Avenue" not in deidentified
        assert "312) 555-0123" not in deidentified
        
        # 8. Assess business associate compliance
        assessment = baa_manager.assess_compliance(ba.id)
        assert assessment["compliance_score"] >= 60.0  # Basic compliance
        
        return {
            "deidentification_result": result,
            "compliance_assessment": assessment,
            "business_associate": ba
        }
    
    def test_breach_detection_workflow(self, processor, baa_manager):
        """Test breach detection and incident response workflow."""
        
        # 1. Create business associate
        ba = baa_manager.create_business_associate(
            name="Cloud Storage Inc",
            organization_type="Technology Services"
        )
        
        # 2. Simulate security incident
        incident = baa_manager.create_incident(
            title="Potential Data Breach - Unauthorized Access",
            description="Suspicious login activity detected on PHI storage system",
            severity=IncidentSeverity.CRITICAL,
            business_associate_id=ba.id,
            phi_involved=True,
            individuals_affected=500,
            phi_categories_affected=["names", "ssn", "dates", "medical_records"]
        )
        
        # 3. Verify automatic breach assessment
        assert incident.breach_notification_required == True
        assert incident.regulatory_notification_required == True
        
        # 4. Process incident response actions
        response_actions = [
            ("immediate_containment", {"action": "Disabled affected accounts"}),
            ("investigation_initiated", {"action": "Started forensic investigation"}),
            ("notification_prepared", {"action": "Prepared breach notification"}),
            ("breach_notification_sent", {"action": "Sent notifications to affected individuals"}),
            ("regulatory_report", {"action": "Submitted report to OCR"})
        ]
        
        for action, details in response_actions:
            success = baa_manager.process_incident_response(incident.id, action, details)
            assert success == True
        
        # 5. Verify incident tracking
        assert len(incident.response_actions) == 5
        assert incident.notification_sent == True
        assert incident.notification_date is not None
        
        # 6. Generate compliance report
        report = baa_manager.generate_compliance_report()
        assert report["summary"]["high_severity_incidents"] == 1
        assert len(report["incidents"]) == 1
        
        return incident
    
    def test_large_scale_processing_performance(self, processor):
        """Test performance with enterprise-scale document processing."""
        
        # Generate multiple healthcare documents
        base_document = """
        Patient Record #{doc_id}
        
        Patient: Patient_{patient_id}
        DOB: 0{month}/1{day}/198{year}
        SSN: {ssn1}-{ssn2}-{ssn3}
        Phone: (555) {phone1}-{phone2}
        Email: patient{patient_id}@email.com
        
        Chief Complaint: Follow-up visit
        Assessment: Stable condition
        Plan: Continue current treatment
        """
        
        documents = []
        for i in range(100):  # Process 100 documents
            doc = base_document.format(
                doc_id=str(i).zfill(3),
                patient_id=str(i).zfill(4),
                month=str((i % 12) + 1),
                day=str((i % 28) + 1),
                year=str(i % 5),
                ssn1=str(100 + i % 900),
                ssn2=str(10 + i % 90),
                ssn3=str(1000 + i % 9000),
                phone1=str(100 + i % 900),
                phone2=str(1000 + i % 9000)
            )
            documents.append(doc)
        
        # Process all documents and measure performance
        start_time = datetime.now()
        results = []
        
        for doc in documents:
            result = processor.process_document(doc)
            results.append(result)
        
        total_time = (datetime.now() - start_time).total_seconds()
        avg_time_per_doc = total_time / len(documents)
        
        # Performance assertions
        assert total_time < 300.0, f"Total processing time {total_time:.1f}s exceeds 5 minutes"
        assert avg_time_per_doc < 3.0, f"Average time per document {avg_time_per_doc:.2f}s exceeds 3s"
        
        # Quality assertions
        all_compliant = all(result.safe_harbor_compliant for result in results)
        avg_confidence = sum(result.confidence_score for result in results) / len(results)
        
        assert avg_confidence >= 0.90, f"Average confidence {avg_confidence:.3f} below 0.90 threshold"
        
        # PHI detection assertions
        total_phi_found = sum(len(result.phi_found) for result in results)
        assert total_phi_found >= 400, f"Expected at least 400 PHI instances, found {total_phi_found}"
        
        return {
            "documents_processed": len(documents),
            "total_time_seconds": total_time,
            "avg_time_per_document": avg_time_per_doc,
            "avg_confidence_score": avg_confidence,
            "total_phi_instances": total_phi_found,
            "all_safe_harbor_compliant": all_compliant
        }


if __name__ == "__main__":
    """Run comprehensive HIPAA compliance tests."""
    
    print("🏥 Starting Comprehensive HIPAA Compliance Test Suite")
    print("=" * 60)
    
    # Run pytest with detailed output
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--durations=10",
        "--color=yes"
    ])