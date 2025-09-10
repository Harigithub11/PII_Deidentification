#!/usr/bin/env python3
"""
Demo Script: Document Processing with Integrated PII Detection

This script demonstrates the complete integration of document processors
with PII detection capabilities, showcasing the unified pipeline.
"""

import asyncio
import tempfile
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import sys
import os

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.core.processing.document_pii_processor import (
    DocumentPIIProcessor,
    PIIProcessingOptions,
    PIIProcessingMode,
    quick_document_pii_analysis_sync
)
from src.core.processing.document_factory import ProcessingOptions, ProcessingMode
from src.core.security.compliance_encryption import ComplianceStandard


def create_sample_document_with_pii():
    """Create a sample document with PII for testing."""
    
    # Create an image with text containing PII
    width, height = 800, 600
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    
    # Try to use a default font, fallback to default if not available
    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except:
        font = ImageFont.load_default()
    
    # Add sample text with PII
    sample_text = [
        "Personal Information Document",
        "",
        "Name: John Smith",
        "Email: john.smith@company.com",
        "Phone: (555) 123-4567",
        "SSN: 123-45-6789",
        "",
        "Address: 123 Main St, Anytown, NY 12345",
        "Date of Birth: 01/15/1985",
        "",
        "Emergency Contact:",
        "Jane Smith - (555) 987-6543",
        "jane.smith@email.com"
    ]
    
    y_position = 50
    for line in sample_text:
        draw.text((50, y_position), line, fill='black', font=font)
        y_position += 35
    
    # Save to temporary file
    temp_file = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
    image.save(temp_file.name, format='PNG')
    
    return Path(temp_file.name)


def demonstrate_basic_integration():
    """Demonstrate basic document PII processing integration."""
    
    print("🔍 Document PII Integration Demo")
    print("=" * 50)
    
    # Create sample document
    print("\n📄 Creating sample document with PII...")
    sample_file = create_sample_document_with_pii()
    print(f"✅ Sample document created: {sample_file}")
    
    try:
        # Initialize processor
        print("\n🚀 Initializing Document PII Processor...")
        processor = DocumentPIIProcessor()
        print("✅ Processor initialized successfully")
        
        # Create processing options
        processing_options = ProcessingOptions(
            mode=ProcessingMode.ENHANCED,
            enhance_for_ocr=True
        )
        
        pii_options = PIIProcessingOptions(
            pii_mode=PIIProcessingMode.COMPREHENSIVE,
            enable_text_pii=True,
            enable_visual_pii=True,
            enable_ocr_pii=True,
            text_confidence_threshold=0.5,
            visual_confidence_threshold=0.6,
            parallel_processing=True
        )
        
        print("\n⚙️ Processing Options:")
        print(f"  • Document Mode: {processing_options.mode.value}")
        print(f"  • PII Mode: {pii_options.pii_mode.value}")
        print(f"  • Text PII Detection: {pii_options.enable_text_pii}")
        print(f"  • Visual PII Detection: {pii_options.enable_visual_pii}")
        print(f"  • OCR PII Detection: {pii_options.enable_ocr_pii}")
        
        # Process document
        print("\n🔄 Processing document with integrated PII detection...")
        result = processor.process_document_with_pii_sync(
            file_path=sample_file,
            processing_options=processing_options,
            pii_options=pii_options
        )
        
        # Display results
        print("\n📊 Processing Results:")
        print(f"  • Success: {result.success}")
        print(f"  • Document Type: {result.document_type.value if result.document_type else 'Unknown'}")
        print(f"  • Page Count: {result.page_count}")
        print(f"  • Processing Time: {result.total_processing_time:.2f}s")
        print(f"  • Overall Risk Level: {result.overall_risk_level.value}")
        
        print("\n🎯 PII Detection Summary:")
        print(f"  • Text Entities Found: {result.total_text_entities}")
        print(f"  • Visual Entities Found: {result.total_visual_entities}")
        print(f"  • Unique PII Types: {len(result.unique_pii_types)}")
        if result.unique_pii_types:
            print(f"  • Types Found: {', '.join(result.unique_pii_types)}")
        
        print("\n⚡ Performance Breakdown:")
        print(f"  • Document Processing: {result.document_processing_time:.2f}s")
        print(f"  • Text PII Detection: {result.text_pii_processing_time:.2f}s")
        print(f"  • Visual PII Detection: {result.visual_pii_processing_time:.2f}s")
        print(f"  • OCR Processing: {result.ocr_processing_time:.2f}s")
        
        print("\n🔧 Operations Performed:")
        for operation in result.operations_performed:
            print(f"  • {operation}")
        
        if result.errors_encountered:
            print("\n⚠️ Errors Encountered:")
            for error in result.errors_encountered:
                print(f"  • {error}")
        
        if result.compliance_flags:
            print("\n🛡️ Compliance Flags:")
            for flag in result.compliance_flags:
                print(f"  • {flag}")
        
        # Test processor statistics
        print("\n📈 Processor Statistics:")
        stats = processor.get_processing_statistics()
        print(f"  • Total Processed: {stats['total_processed']}")
        print(f"  • Success Rate: {stats['success_rate']:.1%}")
        print(f"  • Average Processing Time: {stats['average_processing_time']:.2f}s")
        
        return result
        
    except Exception as e:
        print(f"\n❌ Error during processing: {e}")
        return None
        
    finally:
        # Cleanup
        try:
            sample_file.unlink()
            print(f"\n🧹 Cleaned up temporary file: {sample_file}")
        except Exception:
            pass


def demonstrate_quick_analysis():
    """Demonstrate quick analysis functionality."""
    
    print("\n" + "=" * 50)
    print("🚀 Quick Analysis Demo")
    print("=" * 50)
    
    # Create sample document
    sample_file = create_sample_document_with_pii()
    
    try:
        print("\n⚡ Running quick comprehensive analysis...")
        
        result = quick_document_pii_analysis_sync(
            file_path=sample_file,
            pii_mode=PIIProcessingMode.COMPREHENSIVE,
            confidence_threshold=0.5
        )
        
        print(f"\n📋 Quick Analysis Results:")
        print(f"  • Processing ID: {result.processing_id}")
        print(f"  • Document ID: {result.document_id}")
        print(f"  • Success: {result.success}")
        print(f"  • Total Processing Time: {result.total_processing_time:.2f}s")
        print(f"  • Risk Level: {result.overall_risk_level.value}")
        
        # Get summary
        summary = result.get_summary()
        print(f"\n📊 Summary:")
        for key, value in summary.items():
            if isinstance(value, dict):
                print(f"  • {key}:")
                for sub_key, sub_value in value.items():
                    print(f"    - {sub_key}: {sub_value}")
            else:
                print(f"  • {key}: {value}")
        
        return result
        
    except Exception as e:
        print(f"\n❌ Error during quick analysis: {e}")
        return None
        
    finally:
        # Cleanup
        try:
            sample_file.unlink()
        except Exception:
            pass


def demonstrate_different_modes():
    """Demonstrate different processing modes."""
    
    print("\n" + "=" * 50)
    print("🔄 Different Processing Modes Demo")
    print("=" * 50)
    
    modes = [
        (PIIProcessingMode.TEXT_ONLY, "Text-only PII detection"),
        (PIIProcessingMode.VISUAL_ONLY, "Visual-only PII detection"),
        (PIIProcessingMode.OCR_ENHANCED, "OCR-enhanced PII detection")
    ]
    
    for mode, description in modes:
        print(f"\n📌 Testing: {description}")
        sample_file = create_sample_document_with_pii()
        
        try:
            result = quick_document_pii_analysis_sync(
                file_path=sample_file,
                pii_mode=mode,
                confidence_threshold=0.5
            )
            
            print(f"  • Mode: {mode.value}")
            print(f"  • Success: {result.success}")
            print(f"  • Text Entities: {result.total_text_entities}")
            print(f"  • Visual Entities: {result.total_visual_entities}")
            print(f"  • Processing Time: {result.total_processing_time:.2f}s")
            print(f"  • Operations: {', '.join(result.operations_performed)}")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            
        finally:
            try:
                sample_file.unlink()
            except Exception:
                pass


async def demonstrate_async_processing():
    """Demonstrate asynchronous processing capabilities."""
    
    print("\n" + "=" * 50)
    print("⚡ Asynchronous Processing Demo")
    print("=" * 50)
    
    # Create multiple sample documents
    sample_files = []
    for i in range(3):
        sample_file = create_sample_document_with_pii()
        sample_files.append(sample_file)
    
    try:
        processor = DocumentPIIProcessor()
        
        print(f"\n🚀 Processing {len(sample_files)} documents asynchronously...")
        
        # Process all documents concurrently
        tasks = []
        for i, sample_file in enumerate(sample_files):
            pii_options = PIIProcessingOptions(
                pii_mode=PIIProcessingMode.COMPREHENSIVE,
                parallel_processing=True
            )
            
            task = processor.process_document_with_pii(
                file_path=sample_file,
                document_id=f"doc_{i+1}",
                pii_options=pii_options
            )
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        print(f"\n📊 Async Processing Results:")
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"  • Document {i+1}: Error - {result}")
            else:
                print(f"  • Document {i+1}: Success={result.success}, Time={result.total_processing_time:.2f}s")
        
        # Show processor statistics
        stats = processor.get_processing_statistics()
        print(f"\n📈 Final Statistics:")
        print(f"  • Total Processed: {stats['total_processed']}")
        print(f"  • Average Time: {stats['average_processing_time']:.2f}s")
        
    except Exception as e:
        print(f"\n❌ Error during async processing: {e}")
        
    finally:
        # Cleanup all files
        for sample_file in sample_files:
            try:
                sample_file.unlink()
            except Exception:
                pass


def main():
    """Main demo function."""
    
    print("🎯 Document PII Processing Integration Demo")
    print("This demo showcases the complete integration of document")
    print("processors with PII detection capabilities.")
    print("\n" + "=" * 60)
    
    try:
        # Demonstrate basic integration
        basic_result = demonstrate_basic_integration()
        
        if basic_result and basic_result.success:
            # Demonstrate quick analysis
            demonstrate_quick_analysis()
            
            # Demonstrate different modes
            demonstrate_different_modes()
            
            # Demonstrate async processing
            print("\n🔄 Running async processing demo...")
            asyncio.run(demonstrate_async_processing())
        
        print("\n" + "=" * 60)
        print("✅ Demo completed successfully!")
        print("\nKey Integration Features Demonstrated:")
        print("  • Unified document and PII processing pipeline")
        print("  • Support for multiple document types (PDF, images)")
        print("  • Text, visual, and OCR-based PII detection")
        print("  • Comprehensive risk assessment")
        print("  • Performance monitoring and statistics")
        print("  • Asynchronous processing capabilities")
        print("  • Error handling and recovery")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()