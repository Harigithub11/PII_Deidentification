#!/usr/bin/env python3
"""
Interactive Demo Script for spaCy NLP Analysis Module

This script demonstrates comprehensive spaCy-based natural language processing
capabilities including linguistic analysis, language detection, text complexity
assessment, PII integration, and advanced NLP features.
"""

import sys
import asyncio
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

print("=== spaCy NLP Analysis Module - Interactive Demo ===")
print(f"Started at: {datetime.now()}")

# Sample texts for comprehensive testing
SAMPLE_TEXTS = {
    "simple": "Hello world, this is a simple test message.",
    
    "medical": """
    Chief Complaint: Patient presents with chest pain and shortness of breath.
    
    History of Present Illness: 
    Mr. Robert Williams, a 45-year-old male, reports onset of substernal chest pain 
    3 hours prior to admission. Pain is described as crushing, 8/10 severity, 
    radiating to left arm. Associated with diaphoresis and nausea.
    
    Past Medical History:
    - Hypertension diagnosed in 2015
    - Type 2 Diabetes Mellitus since 2018
    - Family history of coronary artery disease
    
    Current Medications:
    - Lisinopril 10mg daily
    - Metformin 500mg twice daily
    
    Assessment and Plan:
    Acute coronary syndrome suspected. Recommend cardiac catheterization,
    serial troponins, and cardiology consultation with Dr. Sarah Mitchell.
    Contact: smitchell@hospital.org or (555) 123-4567.
    """,
    
    "business": """
    Quarterly Business Report - Q3 2024
    
    Executive Summary:
    Metro Technologies Inc. achieved significant growth in the third quarter, 
    with revenue increasing by 15% compared to Q2. Our artificial intelligence 
    division, led by Dr. John Anderson, launched three innovative products.
    
    Key Performance Indicators:
    - Total Revenue: $2.5 million
    - Customer Acquisition: 1,200 new clients
    - Market Expansion: Entered European markets
    
    Future Outlook:
    The company plans to invest $500,000 in research and development for Q4.
    Strategic partnerships with Google, Microsoft, and Amazon are under negotiation.
    
    Contact Information:
    CEO: Michael Thompson (mthompson@metro-tech.com)
    CFO: Lisa Rodriguez (lrodriguez@metro-tech.com)
    Headquarters: 789 Innovation Drive, San Francisco, CA 94102
    """,
    
    "scientific": """
    Abstract: Machine Learning Applications in Cardiovascular Disease Prediction
    
    Background: Cardiovascular diseases remain the leading cause of mortality worldwide.
    Recent advances in machine learning offer promising avenues for early detection
    and risk stratification. This study evaluated multiple algorithms including
    support vector machines, random forests, and neural networks.
    
    Methods: We analyzed data from 10,000 patients across 15 medical centers.
    Features included demographics, laboratory values, imaging results, and genetic markers.
    The dataset was split 70/30 for training and validation respectively.
    
    Results: The ensemble model achieved an AUC of 0.94 for predicting 5-year
    cardiovascular risk. Sensitivity was 89% and specificity was 91%.
    Key predictive features included troponin levels, ejection fraction,
    and LDL cholesterol concentrations.
    
    Conclusion: Machine learning models demonstrate superior performance compared
    to traditional risk scores. Implementation in clinical practice could
    significantly improve patient outcomes and reduce healthcare costs.
    """,
    
    "multilingual_en": "The quick brown fox jumps over the lazy dog.",
    "multilingual_es": "El zorro marrón rápido salta sobre el perro perezoso.",
    "multilingual_fr": "Le renard brun rapide saute par-dessus le chien paresseux.",
    "multilingual_de": "Der schnelle braune Fuchs springt über den faulen Hund.",
    
    "pii_heavy": """
    Patient Information Form
    
    Personal Details:
    Name: Sarah Elizabeth Johnson
    SSN: 123-45-6789
    Date of Birth: May 20, 1985
    Email: sarah.johnson@email.com
    Phone: (555) 987-6543
    Address: 456 Oak Street, Boston, MA 02101
    
    Financial Information:
    Credit Card: 4532-1234-5678-9012
    Bank Account: 987654321
    Driver's License: D123456789
    
    Emergency Contact:
    Name: Michael Johnson (spouse)
    Phone: (555) 987-6544
    Email: michael.johnson@email.com
    
    Medical Record: MR987654321
    Insurance ID: INS123456789
    """,
    
    "complex_literary": """
    In the labyrinthine corridors of consciousness, where thought and memory
    interweave like gossamer threads in an ethereal tapestry, one finds the
    quintessential paradox of human existence: the simultaneous yearning for
    connection and the inexorable pull toward solitude. This dichotomy,
    perpetually oscillating between the poles of communion and isolation,
    forms the fundamental architecture of the psyche, wherein each individual
    navigates the treacherous waters of interpersonal relationships while
    maintaining the sacred sanctuary of inner contemplation.
    """
}

def demo_language_detection():
    """Demonstrate language detection capabilities."""
    print("\n=== Language Detection Demo ===")
    
    try:
        from src.core.processing.spacy_processor import create_spacy_processor, quick_language_detection
        
        processor = create_spacy_processor()
        
        # Test multilingual texts
        multilingual_texts = {
            "English": SAMPLE_TEXTS["multilingual_en"],
            "Spanish": SAMPLE_TEXTS["multilingual_es"], 
            "French": SAMPLE_TEXTS["multilingual_fr"],
            "German": SAMPLE_TEXTS["multilingual_de"]
        }
        
        print("Testing language detection on multilingual texts:")
        
        for language, text in multilingual_texts.items():
            print(f"\n--- {language} Text ---")
            print(f"Text: '{text}'")
            
            result = processor.detect_language(text)
            
            print(f"Detected Language: {result.primary_language} (confidence: {result.confidence:.2f})")
            print(f"Supported by Model: {result.supported_by_model}")
            print(f"Detection Method: {result.method_used}")
            
            if len(result.detected_languages) > 1:
                print("Alternative languages:")
                for lang, conf in sorted(result.detected_languages.items(), 
                                       key=lambda x: x[1], reverse=True)[1:3]:
                    print(f"  - {lang}: {conf:.2f}")
        
        # Test mixed/unclear text
        print(f"\n--- Testing Mixed Content ---")
        mixed_text = "Hello world! ¿Cómo estás? Bonjour le monde! Guten Tag!"
        result = processor.detect_language(mixed_text)
        print(f"Mixed Text: '{mixed_text}'")
        print(f"Primary Language: {result.primary_language} (confidence: {result.confidence:.2f})")
        
    except Exception as e:
        print(f"Language detection demo failed: {e}")
        print("Make sure spaCy models are installed: python -m spacy download en_core_web_sm")

def demo_linguistic_analysis():
    """Demonstrate comprehensive linguistic analysis."""
    print("\n=== Linguistic Analysis Demo ===")
    
    try:
        from src.core.processing.spacy_processor import create_spacy_processor
        
        processor = create_spacy_processor()
        
        # Analyze different types of text
        for text_type, text in [("simple", SAMPLE_TEXTS["simple"]), 
                               ("business", SAMPLE_TEXTS["business"][:500])]:
            print(f"\n--- Analyzing {text_type.upper()} text ---")
            print(f"Text preview: {text[:100]}...")
            
            result = processor.analyze_text(
                text=text,
                include_entities=True,
                include_pos_tags=True,
                include_dependencies=True,
                include_lemmas=True,
                include_complexity=True,
                include_pii_indicators=True
            )
            
            print(f"\nAnalysis Results:")
            print(f"  - Analysis ID: {result.analysis_id}")
            print(f"  - Language: {result.language}")
            print(f"  - Model Used: {result.model_used}")
            print(f"  - Text Length: {result.text_length} characters")
            print(f"  - Token Count: {len(result.tokens)}")
            print(f"  - Sentence Count: {len(result.sentences)}")
            print(f"  - Entity Count: {len(result.entities)}")
            
            # Show complexity analysis
            print(f"\nText Complexity:")
            print(f"  - Overall Score: {result.complexity.overall_score:.2f}")
            print(f"  - Complexity Level: {result.complexity.level}")
            print(f"  - Vocabulary Diversity: {result.complexity.vocabulary_diversity:.2f}")
            print(f"  - Avg Sentence Length: {result.complexity.average_sentence_length:.1f}")
            
            # Show top entities
            if result.entities:
                print(f"\nTop Entities:")
                for entity in result.entities[:5]:
                    print(f"  - {entity['label']}: '{entity['text']}' (confidence: {entity.get('confidence', 'N/A')})")
            
            # Show PII indicators if any
            if result.pii_indicators:
                print(f"\nPII Indicators Found: {len(result.pii_indicators)}")
                print(f"Privacy Risk Score: {result.privacy_risk_score:.2f}")
                for pii in result.pii_indicators[:3]:
                    print(f"  - {pii.get('type', 'Unknown')}: confidence {pii.get('confidence', 0):.2f}")
            
    except Exception as e:
        print(f"Linguistic analysis demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_text_complexity():
    """Demonstrate text complexity analysis."""
    print("\n=== Text Complexity Analysis Demo ===")
    
    try:
        from src.core.processing.spacy_processor import create_spacy_processor
        
        processor = create_spacy_processor()
        
        # Test different complexity levels
        complexity_samples = {
            "Simple": SAMPLE_TEXTS["simple"],
            "Medical": SAMPLE_TEXTS["medical"][:400],
            "Scientific": SAMPLE_TEXTS["scientific"][:400],
            "Literary": SAMPLE_TEXTS["complex_literary"]
        }
        
        print("Comparing text complexity across different document types:")
        
        for doc_type, text in complexity_samples.items():
            print(f"\n--- {doc_type} Text Complexity ---")
            
            result = processor.analyze_text(
                text=text,
                include_complexity=True
            )
            
            complexity = result.complexity
            print(f"Overall Complexity Score: {complexity.overall_score:.2f}")
            print(f"Complexity Level: {complexity.level}")
            print(f"Vocabulary Diversity: {complexity.vocabulary_diversity:.2f}")
            print(f"Average Sentence Length: {complexity.average_sentence_length:.1f} words")
            
            if hasattr(complexity, 'readability_scores'):
                print("Readability Metrics:")
                for metric, score in complexity.readability_scores.items():
                    print(f"  - {metric.replace('_', ' ').title()}: {score:.1f}")
            
            if complexity.factors:
                print(f"Complexity Factors: {', '.join(complexity.factors[:3])}")
        
    except Exception as e:
        print(f"Text complexity demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_pii_integration():
    """Demonstrate PII integration with linguistic analysis."""
    print("\n=== PII Integration Demo ===")
    
    try:
        from src.core.processing.spacy_processor import create_spacy_processor
        
        processor = create_spacy_processor()
        
        print("Analyzing text with heavy PII content:")
        print(f"Text preview: {SAMPLE_TEXTS['pii_heavy'][:200]}...")
        
        result = processor.analyze_text(
            text=SAMPLE_TEXTS["pii_heavy"],
            include_pii_indicators=True,
            include_entities=True
        )
        
        print(f"\nPII Analysis Results:")
        print(f"  - Privacy Risk Score: {result.privacy_risk_score:.2f}")
        print(f"  - PII Indicators Found: {len(result.pii_indicators)}")
        
        if result.pii_indicators:
            print("\nDetected PII Types:")
            pii_types = {}
            for pii in result.pii_indicators:
                pii_type = pii.get('type', 'Unknown')
                if pii_type in pii_types:
                    pii_types[pii_type] += 1
                else:
                    pii_types[pii_type] = 1
            
            for pii_type, count in sorted(pii_types.items()):
                print(f"  - {pii_type}: {count} instances")
        
        # Compare with standard entities
        print(f"\nStandard Named Entities: {len(result.entities)}")
        if result.entities:
            entity_types = {}
            for entity in result.entities:
                entity_type = entity['label']
                entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
            
            for entity_type, count in sorted(entity_types.items()):
                print(f"  - {entity_type}: {count} instances")
        
    except Exception as e:
        print(f"PII integration demo failed: {e}")
        import traceback
        traceback.print_exc()

async def demo_batch_processing():
    """Demonstrate batch processing capabilities."""
    print("\n=== Batch Processing Demo ===")
    
    try:
        from src.core.services.spacy_service import create_spacy_service
        
        service = create_spacy_service()
        
        # Prepare batch of texts
        batch_texts = [
            SAMPLE_TEXTS["simple"],
            SAMPLE_TEXTS["business"][:300],
            SAMPLE_TEXTS["medical"][:300],
            "This is additional test text for batch processing.",
            "Another sample text to demonstrate concurrent analysis."
        ]
        
        print(f"Processing batch of {len(batch_texts)} texts...")
        
        start_time = time.time()
        result = await service.batch_analyze_texts_async(
            texts=batch_texts,
            language="en",
            batch_size=3
        )
        processing_time = time.time() - start_time
        
        print(f"\nBatch Processing Results:")
        print(f"  - Job ID: {result.job_id}")
        print(f"  - Total Texts: {result.total_texts}")
        print(f"  - Successfully Processed: {result.successful_count}")
        print(f"  - Failed: {result.failed_count}")
        print(f"  - Processing Time: {processing_time:.2f} seconds")
        print(f"  - Average per Text: {processing_time/len(batch_texts):.3f} seconds")
        
        if result.results:
            print(f"\nSample Results:")
            for i, analysis in enumerate(result.results[:3]):
                if analysis:
                    print(f"  Text {i+1}:")
                    print(f"    - Language: {analysis.language}")
                    print(f"    - Tokens: {len(analysis.tokens)}")
                    print(f"    - Entities: {len(analysis.entities)}")
                    print(f"    - Complexity: {analysis.complexity.level if hasattr(analysis.complexity, 'level') else 'N/A'}")
        
        if result.performance_stats:
            print(f"\nPerformance Statistics:")
            for stat, value in result.performance_stats.items():
                if isinstance(value, (int, float)):
                    print(f"  - {stat.replace('_', ' ').title()}: {value}")
        
    except Exception as e:
        print(f"Batch processing demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_text_similarity():
    """Demonstrate text similarity analysis."""
    print("\n=== Text Similarity Demo ===")
    
    try:
        from src.core.services.spacy_service import create_spacy_service
        
        service = create_spacy_service()
        
        # Test similarity between different text pairs
        similarity_pairs = [
            ("Similar Medical Texts", 
             "Patient has chest pain and breathing difficulties.",
             "Patient presents with chest pain and shortness of breath."),
            
            ("Different Topics",
             "The weather is beautiful today with sunny skies.",
             "Quarterly financial reports show increased revenue."),
            
            ("Same Topic, Different Style",
             "Machine learning algorithms improve healthcare outcomes.",
             "AI technology enhances patient care and medical diagnosis.")
        ]
        
        print("Testing text similarity across different pairs:")
        
        for pair_type, text1, text2 in similarity_pairs:
            print(f"\n--- {pair_type} ---")
            print(f"Text 1: '{text1}'")
            print(f"Text 2: '{text2}'")
            
            similarity = service.compute_text_similarity(
                text1=text1,
                text2=text2,
                method="combined"
            )
            
            print(f"Similarity Score: {similarity['similarity_score']:.3f}")
            print(f"Method Used: {similarity['method_used']}")
            
            # Interpret similarity score
            score = similarity['similarity_score']
            if score > 0.8:
                interpretation = "Very Similar"
            elif score > 0.6:
                interpretation = "Similar"
            elif score > 0.4:
                interpretation = "Somewhat Similar"
            elif score > 0.2:
                interpretation = "Slightly Similar"
            else:
                interpretation = "Not Similar"
            
            print(f"Interpretation: {interpretation}")
        
    except Exception as e:
        print(f"Text similarity demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_information_extraction():
    """Demonstrate key information extraction."""
    print("\n=== Information Extraction Demo ===")
    
    try:
        from src.core.services.spacy_service import create_spacy_service
        
        service = create_spacy_service()
        
        print("Extracting key information from medical text:")
        print(f"Text preview: {SAMPLE_TEXTS['medical'][:200]}...")
        
        extracted = service.extract_key_information(
            text=SAMPLE_TEXTS["medical"],
            information_types=["entities", "keywords", "dates", "organizations", "persons"]
        )
        
        print(f"\nExtracted Information:")
        
        for info_type, items in extracted.items():
            if items and isinstance(items, list):
                print(f"\n{info_type.title()}:")
                for item in items[:5]:  # Show top 5
                    if isinstance(item, dict):
                        text = item.get('text', str(item))
                        confidence = item.get('confidence', 'N/A')
                        print(f"  - {text} (confidence: {confidence})")
                    else:
                        print(f"  - {item}")
        
        print(f"\nBusiness Text Information Extraction:")
        print(f"Text preview: {SAMPLE_TEXTS['business'][:200]}...")
        
        business_extracted = service.extract_key_information(
            text=SAMPLE_TEXTS["business"],
            information_types=["entities", "keywords", "organizations", "persons"]
        )
        
        for info_type, items in business_extracted.items():
            if items and isinstance(items, list) and len(items) > 0:
                print(f"\n{info_type.title()} (Business):")
                for item in items[:3]:
                    if isinstance(item, dict):
                        text = item.get('text', str(item))
                        print(f"  - {text}")
                    else:
                        print(f"  - {item}")
        
    except Exception as e:
        print(f"Information extraction demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_model_management():
    """Demonstrate model management capabilities."""
    print("\n=== Model Management Demo ===")
    
    try:
        from src.core.models.spacy_models import get_model_manager
        
        manager = get_model_manager()
        
        print("Current Model Manager Status:")
        model_info = manager.get_model_info()
        
        print(f"  - Total Models: {model_info.get('total_models', 0)}")
        print(f"  - Loaded Models: {model_info.get('loaded_models', 0)}")
        print(f"  - Max Loaded Models: {model_info.get('max_loaded_models', 'N/A')}")
        
        if 'models' in model_info and model_info['models']:
            print("\nLoaded Models:")
            for model_name, model_details in model_info['models'].items():
                if isinstance(model_details, dict):
                    language = model_details.get('language', 'Unknown')
                    is_loaded = model_details.get('is_loaded', False)
                    status = "✓ Loaded" if is_loaded else "○ Not Loaded"
                    print(f"  - {model_name} ({language}): {status}")
        
        # Try to load a model
        print(f"\nAttempting to load English model...")
        try:
            model = manager.get_model(language="en")
            if model and model.is_loaded:
                print(f"  ✓ Successfully loaded: {model.model_name}")
                print(f"  - Language: {model.language}")
                print(f"  - Pipeline Components: {len(model.nlp.pipe_names) if model.nlp else 0}")
            else:
                print(f"  ✗ Failed to load model")
        except Exception as e:
            print(f"  ✗ Model loading error: {e}")
        
        # Show supported languages
        print(f"\nSupported Languages: {', '.join(manager.default_models.keys())}")
        
    except Exception as e:
        print(f"Model management demo failed: {e}")
        import traceback
        traceback.print_exc()

def demo_performance_metrics():
    """Demonstrate performance monitoring."""
    print("\n=== Performance Monitoring Demo ===")
    
    try:
        from src.core.services.spacy_service import create_spacy_service
        
        service = create_spacy_service()
        
        # Perform some operations to generate metrics
        print("Performing sample operations to generate performance metrics...")
        
        # Single analysis
        start_time = time.time()
        result1 = service.analyze_text_sync(SAMPLE_TEXTS["simple"])
        single_time = time.time() - start_time
        
        # Batch analysis
        start_time = time.time()
        batch_texts = [SAMPLE_TEXTS["simple"], SAMPLE_TEXTS["business"][:200]]
        batch_results = service.batch_analyze_texts_sync(batch_texts)
        batch_time = time.time() - start_time
        
        print(f"\nPerformance Results:")
        print(f"  - Single Analysis Time: {single_time:.3f} seconds")
        print(f"  - Batch Analysis Time: {batch_time:.3f} seconds")
        print(f"  - Time per Text (batch): {batch_time/len(batch_texts):.3f} seconds")
        print(f"  - Efficiency Gain: {single_time/(batch_time/len(batch_texts)):.1f}x faster")
        
        # Get service performance stats
        stats = service.get_performance_stats()
        
        if stats:
            print(f"\nService Performance Statistics:")
            for stat_name, stat_value in stats.items():
                if isinstance(stat_value, (int, float)):
                    if 'time' in stat_name.lower():
                        print(f"  - {stat_name.replace('_', ' ').title()}: {stat_value:.3f}s")
                    else:
                        print(f"  - {stat_name.replace('_', ' ').title()}: {stat_value}")
        
    except Exception as e:
        print(f"Performance monitoring demo failed: {e}")
        import traceback
        traceback.print_exc()

def interactive_demo():
    """Run interactive demo with user choices."""
    print("\n=== Interactive Demo Menu ===")
    
    demos = {
        "1": ("Language Detection", demo_language_detection),
        "2": ("Linguistic Analysis", demo_linguistic_analysis), 
        "3": ("Text Complexity Analysis", demo_text_complexity),
        "4": ("PII Integration", demo_pii_integration),
        "5": ("Batch Processing", lambda: asyncio.run(demo_batch_processing())),
        "6": ("Text Similarity", demo_text_similarity),
        "7": ("Information Extraction", demo_information_extraction),
        "8": ("Model Management", demo_model_management),
        "9": ("Performance Metrics", demo_performance_metrics),
        "a": ("Run All Demos", None)
    }
    
    while True:
        print(f"\nAvailable Demos:")
        for key, (name, _) in demos.items():
            print(f"  {key}. {name}")
        print(f"  q. Quit")
        
        choice = input(f"\nEnter your choice (1-9, a, or q): ").strip().lower()
        
        if choice == 'q':
            print("Demo session ended.")
            break
        elif choice == 'a':
            print("\n=== Running All Demos ===")
            for key, (name, func) in demos.items():
                if key != 'a' and func:
                    print(f"\n{'='*50}")
                    print(f"Running: {name}")
                    print(f"{'='*50}")
                    try:
                        func()
                    except KeyboardInterrupt:
                        print(f"\nDemo interrupted by user")
                        break
                    except Exception as e:
                        print(f"Demo failed: {e}")
                    
                    input("\nPress Enter to continue to next demo...")
            print(f"\n=== All Demos Completed ===")
        elif choice in demos and demos[choice][1]:
            name, func = demos[choice]
            print(f"\n{'='*50}")
            print(f"Running: {name}")
            print(f"{'='*50}")
            try:
                func()
            except KeyboardInterrupt:
                print(f"\nDemo interrupted by user")
            except Exception as e:
                print(f"Demo failed: {e}")
                import traceback
                traceback.print_exc()
        else:
            print(f"Invalid choice. Please enter 1-9, a, or q.")

def check_dependencies():
    """Check if required dependencies are available."""
    print("\n=== Checking Dependencies ===")
    
    dependencies = [
        ("spacy", "spaCy NLP library"),
        ("numpy", "NumPy for numerical computing"),
        ("asyncio", "Asyncio for async operations")
    ]
    
    missing_deps = []
    
    for module, description in dependencies:
        try:
            __import__(module)
            print(f"  [OK] {description}")
        except ImportError:
            print(f"  [ERROR] {description} - MISSING")
            missing_deps.append(module)
    
    # Check for spaCy models
    try:
        import spacy
        try:
            spacy.load("en_core_web_sm")
            print(f"  [OK] English spaCy model (en_core_web_sm)")
        except OSError:
            print(f"  [ERROR] English spaCy model - MISSING")
            print(f"    Install with: python -m spacy download en_core_web_sm")
    except ImportError:
        pass
    
    # Check project modules
    project_modules = [
        ("src.core.processing.spacy_processor", "spaCy Processor"),
        ("src.core.services.spacy_service", "spaCy Service"),
        ("src.core.models.spacy_models", "spaCy Models")
    ]
    
    for module, description in project_modules:
        try:
            __import__(module)
            print(f"  [OK] {description}")
        except ImportError as e:
            print(f"  [ERROR] {description} - MISSING ({e})")
            missing_deps.append(module)
    
    if missing_deps:
        print(f"\n[WARNING] Some dependencies are missing.")
        print(f"Some demos may not work properly.")
    else:
        print(f"\n[SUCCESS] All dependencies are available!")
    
    return len(missing_deps) == 0

def main():
    """Main demo function."""
    print("\nWelcome to the spaCy NLP Analysis Demo!")
    print("This demo showcases comprehensive natural language processing capabilities")
    print("including linguistic analysis, language detection, complexity assessment,")
    print("PII integration, batch processing, and advanced NLP features.")
    
    # Check dependencies
    deps_ok = check_dependencies()
    
    if not deps_ok:
        response = input(f"\nSome dependencies are missing. Continue anyway? (y/n): ").strip().lower()
        if response != 'y':
            print("Demo cancelled.")
            return
    
    # Run interactive demo
    try:
        interactive_demo()
    except KeyboardInterrupt:
        print(f"\n\nDemo interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nDemo failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\nThank you for exploring the spaCy NLP Analysis Module!")
    print(f"For more information, check the documentation and API endpoints.")

if __name__ == "__main__":
    main()