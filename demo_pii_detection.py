#!/usr/bin/env python3
"""
Demo script for PII Detection Module

This script demonstrates the PII detection functionality with real examples.
"""

import sys
from datetime import datetime

print("=== PII Detection Module - Functional Demo ===")
print(f"Started at: {datetime.now()}")

# Sample texts for testing
SAMPLE_TEXTS = {
    "medical": """
Patient Name: John Smith
DOB: 01/15/1985
SSN: 123-45-6789
Phone: (555) 123-4567
Email: john.smith@email.com
Address: 123 Main Street, New York, NY 10001
Medical Record Number: MR123456
Diagnosis: Type 2 Diabetes Mellitus
""",
    "financial": """
Customer: Jane Doe
Account: 4532-1234-5678-9012
Routing: 021000021
Phone: (555) 987-6543
Email: jane.doe@bank.com
Income: $75,000 annually
""",
    "minimal": """
Hello, this is a test message without any sensitive information.
Just some plain text for testing purposes.
""",
    "mixed": """
Conference attendee: Dr. Michael Johnson
Institution: Metro General Hospital
Contact: mjohnson@hospital.org
Phone: (555) 444-7890
License: MD123456789
Research focus: Cardiology and patient care optimization
"""
}

def demo_presidio_detection():
    """Demonstrate Presidio-based PII detection."""
    print("\n=== Presidio PII Detection Demo ===")
    
    try:
        from presidio_analyzer import AnalyzerEngine
        
        # Initialize analyzer
        analyzer = AnalyzerEngine()
        
        for text_type, text in SAMPLE_TEXTS.items():
            print(f"\n--- Analyzing {text_type.upper()} text ---")
            print(f"Text: {text.strip()[:100]}...")
            
            # Analyze for PII
            results = analyzer.analyze(text=text, language='en')
            
            print(f"Found {len(results)} PII entities:")
            
            for result in results:
                entity_text = text[result.start:result.end]
                print(f"  - {result.entity_type}: '{entity_text}' (confidence: {result.score:.2f})")
            
            if not results:
                print("  - No PII entities detected")
    
    except Exception as e:
        print(f"Demo failed: {e}")

def demo_risk_assessment():
    """Demonstrate risk level assessment based on detected entities."""
    print("\n=== Risk Assessment Demo ===")
    
    # Simulate different risk scenarios
    scenarios = {
        "Low Risk": ["PERSON"],
        "Medium Risk": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION", "ORGANIZATION", "DATE_TIME"],
        "High Risk": ["PERSON", "EMAIL_ADDRESS", "US_DRIVER_LICENSE"],
        "Critical Risk": ["PERSON", "SSN", "CREDIT_CARD"]
    }
    
    def calculate_risk(entity_types):
        critical_entities = {"SSN", "CREDIT_CARD", "US_PASSPORT"}
        high_risk_entities = {"US_DRIVER_LICENSE", "US_BANK_NUMBER"}
        
        if any(entity in critical_entities for entity in entity_types):
            return "CRITICAL"
        elif any(entity in high_risk_entities for entity in entity_types):
            return "HIGH"
        elif len(entity_types) > 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    for scenario_name, entities in scenarios.items():
        calculated_risk = calculate_risk(entities)
        print(f"{scenario_name}: {entities} -> Risk Level: {calculated_risk}")

def demo_anonymization():
    """Demonstrate text anonymization."""
    print("\n=== Text Anonymization Demo ===")
    
    try:
        from presidio_anonymizer import AnonymizerEngine
        from presidio_analyzer import AnalyzerEngine
        
        analyzer = AnalyzerEngine()
        anonymizer = AnonymizerEngine()
        
        # Use medical text for demo
        text = SAMPLE_TEXTS["medical"]
        
        print("Original text:")
        print(f"'{text.strip()}'")
        
        # Analyze for PII
        analyzer_results = analyzer.analyze(text=text, language='en')
        
        # Anonymize
        anonymized_result = anonymizer.anonymize(text=text, analyzer_results=analyzer_results)
        
        print("\nAnonymized text:")
        print(f"'{anonymized_result.text}'")
        
        print(f"\nAnonymized {len(analyzer_results)} PII entities")
        
    except Exception as e:
        print(f"Anonymization demo failed: {e}")

def demo_compliance_considerations():
    """Demonstrate compliance considerations."""
    print("\n=== Compliance Considerations Demo ===")
    
    compliance_rules = {
        "HIPAA": {
            "required_encryption": True,
            "retention_years": 6,
            "sensitive_entities": ["SSN", "MEDICAL_LICENSE", "PHONE_NUMBER", "EMAIL_ADDRESS"],
            "description": "Healthcare data protection"
        },
        "GDPR": {
            "required_encryption": True,
            "retention_years": 7,
            "sensitive_entities": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "LOCATION"],
            "description": "European data protection regulation"
        },
        "PCI_DSS": {
            "required_encryption": True,
            "retention_years": 1,
            "sensitive_entities": ["CREDIT_CARD", "US_BANK_NUMBER"],
            "description": "Payment card industry security"
        }
    }
    
    # Sample entities found in text
    detected_entities = ["PERSON", "SSN", "CREDIT_CARD", "EMAIL_ADDRESS"]
    
    print("Detected entities:", detected_entities)
    print("\nCompliance analysis:")
    
    for standard, rules in compliance_rules.items():
        applicable_entities = [e for e in detected_entities if e in rules["sensitive_entities"]]
        if applicable_entities:
            print(f"\n{standard} ({rules['description']}):")
            print(f"  - Applies to: {applicable_entities}")
            print(f"  - Encryption required: {rules['required_encryption']}")
            print(f"  - Retention period: {rules['retention_years']} years")

def main():
    """Run all demos."""
    print("This demo shows the capabilities of the PII Detection Module:")
    print("1. Microsoft Presidio integration for entity detection")
    print("2. Risk assessment based on detected entities")
    print("3. Text anonymization capabilities")
    print("4. Compliance framework considerations")
    
    demos = [
        demo_presidio_detection,
        demo_risk_assessment,
        demo_anonymization,
        demo_compliance_considerations
    ]
    
    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"Demo failed: {e}")
            print("Continuing with next demo...")
    
    print("\n=== Demo Complete ===")
    print("Key features demonstrated:")
    print("- PII entity detection using Microsoft Presidio")
    print("- Risk level assessment algorithms")
    print("- Text anonymization and redaction")
    print("- Compliance framework integration (HIPAA, GDPR, PCI-DSS)")
    print("- Multi-domain support (medical, financial, general)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())