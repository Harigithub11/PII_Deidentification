#!/usr/bin/env python3
"""
Comprehensive Redaction System Demo

This script demonstrates the full range of redaction capabilities including:
- Text redaction with multiple methods
- Visual redaction with various techniques
- Policy-driven redaction
- Pseudonymization and generalization
- Performance and quality metrics

Run with: python demo_comprehensive_redaction.py
"""

import asyncio
import time
import numpy as np
from PIL import Image, ImageDraw
from pathlib import Path
import json
from typing import List, Dict, Any

# Core imports
from src.core.config.policies.base import PIIType, RedactionMethod
from src.core.config.policy_models import PolicyContext
from src.core.models.ner_models import PIIEntity
from src.core.models.visual_models import VisualPIIEntity, BoundingBox, VisualPIIType
from src.core.services.redaction_engine import (
    get_redaction_engine, RedactionRequest, RedactionType, 
    RedactionParameters, RedactionIntensity
)
from src.core.services.pseudonymization_service import (
    get_pseudonymization_service, PseudonymizationConfig, 
    GeneralizationConfig, PseudonymizationMethod, GeneralizationLevel
)
from src.core.services.policy_redaction_service import (
    get_policy_redaction_service, PolicyRedactionRequest
)
from src.core.security.compliance_encryption import DataClassification


class RedactionDemo:
    """Comprehensive redaction system demonstration."""
    
    def __init__(self):
        self.redaction_engine = get_redaction_engine()
        self.pseudonymization_service = get_pseudonymization_service()
        self.policy_redaction_service = get_policy_redaction_service()
        
        # Sample data for demonstrations
        self.sample_text = """
        Patient Information:
        Name: John Michael Smith
        Date of Birth: 1985-03-15
        SSN: 123-45-6789
        Phone: (555) 987-6543
        Email: john.smith@healthcorp.com
        Address: 1234 Medical Drive, Healthcare City, HC 12345
        
        Medical Record:
        Dr. Sarah Johnson treated patient for hypertension.
        Prescription: Lisinopril 10mg daily
        Next appointment: 2024-06-15
        Insurance ID: INS123456789
        """
        
        self.sample_entities = [
            PIIEntity("John Michael Smith", PIIType.NAME, 34, 51, 0.98),
            PIIEntity("1985-03-15", PIIType.DATE_OF_BIRTH, 70, 80, 0.95),
            PIIEntity("123-45-6789", PIIType.SSN, 90, 101, 0.99),
            PIIEntity("(555) 987-6543", PIIType.PHONE, 111, 125, 0.94),
            PIIEntity("john.smith@healthcorp.com", PIIType.EMAIL, 135, 161, 0.97),
            PIIEntity("1234 Medical Drive, Healthcare City, HC 12345", PIIType.ADDRESS, 171, 216, 0.92),
            PIIEntity("Dr. Sarah Johnson", PIIType.NAME, 252, 268, 0.93),
            PIIEntity("2024-06-15", PIIType.DATE_OF_BIRTH, 350, 360, 0.89),
            PIIEntity("INS123456789", PIIType.MEDICAL_RECORD, 391, 403, 0.96)
        ]
        
        print("🎯 Comprehensive Redaction System Demo")
        print("=" * 50)
    
    def demonstrate_text_redaction_methods(self):
        """Demonstrate various text redaction methods."""
        print("\n📝 TEXT REDACTION METHODS")
        print("-" * 30)
        
        # Test different redaction methods
        methods_to_test = [
            (RedactionMethod.DELETE, "Complete deletion"),
            (RedactionMethod.MASK_ASTERISK, "Asterisk masking"),
            (RedactionMethod.MASK_X, "X character masking"),
            (RedactionMethod.REDACTED_LABEL, "Standard [REDACTED] label"),
            (RedactionMethod.PLACEHOLDER, "Custom placeholder"),
            (RedactionMethod.PARTIAL_MASK, "Partial masking"),
            (RedactionMethod.HASH, "Hash replacement")
        ]
        
        # Focus on just the name for clarity in demo
        name_entity = [self.sample_entities[0]]  # John Michael Smith
        
        for method, description in methods_to_test:
            print(f"\n{description.upper()}:")
            
            # Configure parameters
            parameters = RedactionParameters(
                method=method,
                intensity=RedactionIntensity.MEDIUM,
                custom_placeholder="[PATIENT_NAME]" if method == RedactionMethod.PLACEHOLDER else None,
                preserve_length=(method == RedactionMethod.MASK_ASTERISK)
            )
            
            # Create and execute request
            request = RedactionRequest(
                redaction_type=RedactionType.TEXT,
                content=self.sample_text,
                entities=name_entity,
                parameters=parameters
            )
            
            result = self.redaction_engine.redact(request)
            
            if result.success:
                # Show just the relevant line
                lines = result.redacted_content.split('\n')
                for line in lines:
                    if 'Name:' in line:
                        print(f"  Original: Name: John Michael Smith")
                        print(f"  Redacted: {line.strip()}")
                        break
                
                print(f"  ⚡ Processing time: {result.processing_time_seconds:.3f}s")
                print(f"  📊 Quality score: {result.quality_score:.2f}")
            else:
                print(f"  ❌ Failed: {result.error_message}")
    
    def demonstrate_visual_redaction(self):
        """Demonstrate visual redaction methods."""
        print("\n🖼️  VISUAL REDACTION METHODS")
        print("-" * 30)
        
        # Create a test image with text and shapes
        img_width, img_height = 400, 300
        test_image = np.ones((img_height, img_width, 3), dtype=np.uint8) * 255  # White background
        
        # Convert to PIL for drawing
        pil_img = Image.fromarray(test_image)
        draw = ImageDraw.Draw(pil_img)
        
        # Draw some "PII" elements
        draw.rectangle([50, 50, 150, 100], fill=(200, 200, 200))  # Face region
        draw.text((60, 65), "FACE", fill=(0, 0, 0))
        
        draw.rectangle([200, 120, 350, 160], fill=(150, 150, 150))  # Signature region
        draw.text((220, 135), "SIGNATURE", fill=(0, 0, 0))
        
        # Convert back to numpy
        test_image = np.array(pil_img)
        
        # Define visual entities
        visual_entities = [
            VisualPIIEntity(
                entity_type=VisualPIIType.FACE,
                confidence=0.95,
                bounding_box=BoundingBox(x=50, y=50, width=100, height=50)
            ),
            VisualPIIEntity(
                entity_type=VisualPIIType.SIGNATURE,
                confidence=0.92,
                bounding_box=BoundingBox(x=200, y=120, width=150, height=40)
            )
        ]
        
        # Test different visual redaction methods
        visual_methods = [
            (RedactionMethod.BLACKOUT, "Black fill", (0, 0, 0)),
            (RedactionMethod.BLUR, "Blur effect", None),
            (RedactionMethod.PIXELATE, "Pixelation", None),
            (RedactionMethod.MOSAIC, "Mosaic tiles", None),
            (RedactionMethod.NOISE, "Noise overlay", None)
        ]
        
        for method, description, color in visual_methods:
            print(f"\n{description.upper()}:")
            
            parameters = RedactionParameters(
                method=method,
                intensity=RedactionIntensity.HIGH,
                color=color if color else (0, 0, 0)
            )
            
            request = RedactionRequest(
                redaction_type=RedactionType.VISUAL,
                content=test_image.copy(),
                entities=visual_entities,
                parameters=parameters
            )
            
            result = self.redaction_engine.redact(request)
            
            if result.success:
                print(f"  ✅ Successfully redacted {len(result.entities_redacted)} regions")
                print(f"  ⚡ Processing time: {result.processing_time_seconds:.3f}s")
                print(f"  📊 Quality score: {result.quality_score:.2f}")
                
                # Save result image
                output_path = f"demo_output_visual_{method.value}.png"
                result_image = Image.fromarray(result.redacted_content)
                result_image.save(output_path)
                print(f"  💾 Saved result to: {output_path}")
            else:
                print(f"  ❌ Failed: {result.error_message}")
    
    def demonstrate_pseudonymization(self):
        """Demonstrate pseudonymization capabilities."""
        print("\n🎭 PSEUDONYMIZATION DEMONSTRATION")
        print("-" * 35)
        
        # Test data for pseudonymization
        test_data = [
            ("John Michael Smith", PIIType.NAME),
            ("john.smith@healthcorp.com", PIIType.EMAIL),
            ("(555) 987-6543", PIIType.PHONE),
            ("1234 Medical Drive, Healthcare City", PIIType.ADDRESS),
            ("123-45-6789", PIIType.SSN),
            ("HealthCorp Inc", PIIType.ORGANIZATION)
        ]
        
        config = PseudonymizationConfig(
            method=PseudonymizationMethod.CONSISTENT_HASH,
            preserve_format=True,
            consistency_key="demo_2024"
        )
        
        print("\nCONSISTENT PSEUDONYMIZATION:")
        print("Original → Pseudonymized")
        
        for original_value, pii_type in test_data:
            result = self.pseudonymization_service.pseudonymize(
                original_value, pii_type, config
            )
            
            if result.success:
                print(f"  {original_value} → {result.anonymized_value}")
            else:
                print(f"  ❌ {original_value} → Failed: {result.error_message}")
        
        # Test consistency
        print("\nCONSISTENCY TEST:")
        name = "John Michael Smith"
        result1 = self.pseudonymization_service.pseudonymize(name, PIIType.NAME, config)
        result2 = self.pseudonymization_service.pseudonymize(name, PIIType.NAME, config)
        
        print(f"  First call:  {name} → {result1.anonymized_value}")
        print(f"  Second call: {name} → {result2.anonymized_value}")
        print(f"  Consistent: {'✅ Yes' if result1.anonymized_value == result2.anonymized_value else '❌ No'}")
    
    def demonstrate_generalization(self):
        """Demonstrate data generalization capabilities."""
        print("\n📊 DATA GENERALIZATION DEMONSTRATION")
        print("-" * 37)
        
        # Test data for generalization
        test_cases = [
            ("Ages", [("25", PIIType.AGE), ("45", PIIType.AGE), ("17", PIIType.AGE), ("72", PIIType.AGE)]),
            ("Incomes", [("35000", PIIType.INCOME), ("75000", PIIType.INCOME), ("120000", PIIType.INCOME)]),
            ("Dates", [("1985-03-15", PIIType.DATE_OF_BIRTH), ("1992-11-22", PIIType.DATE_OF_BIRTH)])
        ]
        
        levels = [
            (GeneralizationLevel.MINIMAL, "Minimal"),
            (GeneralizationLevel.MODERATE, "Moderate"),
            (GeneralizationLevel.HIGH, "High")
        ]
        
        for category, test_values in test_cases:
            print(f"\n{category.upper()} GENERALIZATION:")
            
            for level, level_name in levels:
                print(f"\n  {level_name} Level:")
                config = GeneralizationConfig(
                    level=level,
                    preserve_utility=True
                )
                
                for value, pii_type in test_values:
                    result = self.pseudonymization_service.generalize(
                        value, pii_type, config
                    )
                    
                    if result.success:
                        print(f"    {value} → {result.anonymized_value}")
                    else:
                        print(f"    ❌ {value} → Failed")
    
    async def demonstrate_policy_driven_redaction(self):
        """Demonstrate policy-driven redaction."""
        print("\n🛡️  POLICY-DRIVEN REDACTION")
        print("-" * 28)
        
        # Create policy context
        context = PolicyContext(
            user_id="demo_user",
            document_type="medical_record",
            compliance_standard="HIPAA",
            processing_purpose="demonstration",
            data_classification=DataClassification.CONFIDENTIAL.value,
            geographic_location="US"
        )
        
        print("Policy Context:")
        print(f"  📋 Document Type: {context.document_type}")
        print(f"  🏥 Compliance: {context.compliance_standard}")
        print(f"  🔐 Classification: {context.data_classification}")
        print(f"  🌍 Location: {context.geographic_location}")
        
        # Create policy redaction request
        request = PolicyRedactionRequest(
            request_id="demo_policy_001",
            content=self.sample_text,
            entities=self.sample_entities[:5],  # Use first 5 entities
            context=context,
            redaction_type=RedactionType.TEXT
        )
        
        print(f"\n📝 Original content preview:")
        lines = self.sample_text.strip().split('\n')
        for line in lines[1:6]:  # Show first few lines
            print(f"  {line.strip()}")
        
        # Get redaction preview first
        print(f"\n🔍 REDACTION PREVIEW:")
        preview = self.policy_redaction_service.get_redaction_preview(
            request, include_policy_details=True
        )
        
        if preview["success"]:
            print(f"  📊 Total entities: {preview['total_entities']}")
            print(f"  ⚖️  Policy decisions: {preview['policy_decisions']}")
            print(f"  ⚠️  Violations: {preview['violations']}")
            
            print("  🔧 Redaction methods to be applied:")
            for method, info in preview["redaction_methods"].items():
                print(f"    • {method}: {info['entity_count']} entities")
        
        # Execute policy-driven redaction
        print(f"\n⚡ EXECUTING POLICY-DRIVEN REDACTION...")
        start_time = time.time()
        result = await self.policy_redaction_service.redact_with_policy_async(request)
        end_time = time.time()
        
        if result.success:
            print(f"✅ Policy redaction successful!")
            print(f"⚡ Processing time: {result.processing_time_seconds:.3f}s")
            print(f"📊 Entities processed: {result.metadata.get('redacted_entities', 0)}")
            
            print(f"\n📝 Redacted content preview:")
            lines = result.redacted_content.strip().split('\n')
            for line in lines[1:6]:  # Show first few lines
                if line.strip():
                    print(f"  {line.strip()}")
            
            print(f"\n⚖️  Policy decisions made:")
            for decision in result.policy_decisions[:3]:  # Show first 3
                print(f"  • {decision.pii_type.value}: {decision.decision_type.value}")
                if decision.redaction_method:
                    print(f"    Method: {decision.redaction_method.value}")
                print(f"    Confidence: {decision.confidence:.2f}")
        else:
            print(f"❌ Policy redaction failed: {result.error_message}")
    
    def demonstrate_performance_metrics(self):
        """Demonstrate performance and quality metrics."""
        print("\n⚡ PERFORMANCE & QUALITY METRICS")
        print("-" * 33)
        
        # Test different content sizes
        sizes = [
            (100, "Small"),
            (1000, "Medium"), 
            (10000, "Large")
        ]
        
        print("Performance test with different content sizes:")
        
        for char_count, size_name in sizes:
            # Generate content of specified size
            test_content = (self.sample_text * ((char_count // len(self.sample_text)) + 1))[:char_count]
            
            # Generate proportional entities
            entity_count = max(1, char_count // 200)  # 1 entity per ~200 chars
            test_entities = (self.sample_entities * ((entity_count // len(self.sample_entities)) + 1))[:entity_count]
            
            # Adjust entity positions to fit content
            for i, entity in enumerate(test_entities):
                entity.start = min(entity.start + (i * 50), len(test_content) - 10)
                entity.end = min(entity.start + len(entity.text), len(test_content))
            
            print(f"\n{size_name.upper()} CONTENT ({char_count} chars, {len(test_entities)} entities):")
            
            # Test with different methods
            methods = [RedactionMethod.DELETE, RedactionMethod.REDACTED_LABEL, RedactionMethod.MASK_ASTERISK]
            
            for method in methods:
                parameters = RedactionParameters(
                    method=method,
                    intensity=RedactionIntensity.MEDIUM
                )
                
                request = RedactionRequest(
                    redaction_type=RedactionType.TEXT,
                    content=test_content,
                    entities=test_entities,
                    parameters=parameters
                )
                
                start_time = time.time()
                result = self.redaction_engine.redact(request)
                end_time = time.time()
                
                if result.success:
                    throughput = len(test_entities) / result.processing_time_seconds
                    print(f"  {method.value:15} | {result.processing_time_seconds:6.3f}s | {throughput:6.1f} entities/s | Q:{result.quality_score:.2f}")
    
    def demonstrate_service_statistics(self):
        """Show service statistics and capabilities."""
        print("\n📈 SERVICE STATISTICS")
        print("-" * 20)
        
        # Get engine statistics
        redaction_stats = self.redaction_engine.get_stats()
        print("Redaction Engine Stats:")
        for key, value in redaction_stats.items():
            print(f"  {key}: {value}")
        
        # Get pseudonymization statistics
        pseudo_stats = self.pseudonymization_service.get_mapping_stats()
        print("\nPseudonymization Service Stats:")
        for key, value in pseudo_stats.items():
            print(f"  {key}: {value}")
        
        # Show supported methods
        print("\nSupported Redaction Methods:")
        text_methods = self.redaction_engine.get_supported_methods(RedactionType.TEXT)
        visual_methods = self.redaction_engine.get_supported_methods(RedactionType.VISUAL)
        
        print(f"  📝 Text methods: {len(text_methods)}")
        for method in text_methods[:5]:  # Show first 5
            print(f"    • {method.value}")
        
        print(f"  🖼️  Visual methods: {len(visual_methods)}")
        for method in visual_methods[:5]:  # Show first 5
            print(f"    • {method.value}")
    
    async def run_full_demo(self):
        """Run the complete demonstration."""
        print("🚀 Starting comprehensive redaction demo...\n")
        
        try:
            # Run all demonstrations
            self.demonstrate_text_redaction_methods()
            self.demonstrate_visual_redaction()
            self.demonstrate_pseudonymization()
            self.demonstrate_generalization()
            await self.demonstrate_policy_driven_redaction()
            self.demonstrate_performance_metrics()
            self.demonstrate_service_statistics()
            
            print("\n" + "=" * 50)
            print("✅ DEMO COMPLETED SUCCESSFULLY!")
            print("\nKey Features Demonstrated:")
            print("  📝 Text redaction with 7+ methods")
            print("  🖼️  Visual redaction with 5+ techniques") 
            print("  🎭 Consistent pseudonymization")
            print("  📊 Multi-level data generalization")
            print("  🛡️  Policy-driven automated redaction")
            print("  ⚡ Performance optimization")
            print("  📈 Quality metrics and statistics")
            
            print(f"\n💾 Output files generated:")
            print("  • demo_output_visual_*.png (visual redaction samples)")
            
        except Exception as e:
            print(f"\n❌ Demo failed with error: {e}")
            import traceback
            traceback.print_exc()


async def main():
    """Main demo execution function."""
    demo = RedactionDemo()
    await demo.run_full_demo()


if __name__ == "__main__":
    # Run the demo
    asyncio.run(main())