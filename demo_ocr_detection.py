#!/usr/bin/env python3
"""
OCR Detection Demonstration Script

This script demonstrates the OCR functionality of the PII De-identification System with:
- Text extraction from images and PDFs using multiple OCR engines
- PII detection in extracted text
- Quality assessment and confidence scoring
- Batch processing capabilities
- Performance benchmarking
- Real-world document processing examples

Usage:
    python demo_ocr_detection.py [--mode MODE] [--engine ENGINE] [--input INPUT_PATH]
    
Examples:
    python demo_ocr_detection.py --mode interactive
    python demo_ocr_detection.py --mode batch --input ./test_documents/
    python demo_ocr_detection.py --mode benchmark --engine tesseract
"""

import argparse
import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import List, Dict, Any
import tempfile
import sys

# Add src to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

try:
    from PIL import Image, ImageDraw, ImageFont
    import numpy as np
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, TaskID
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    import click
except ImportError as e:
    print(f"Missing dependencies: {e}")
    print("Please install: pip install pillow rich click")
    sys.exit(1)

# Import OCR components
try:
    from core.models.ocr_models import (
        OCREngine, LanguageCode, get_available_ocr_engines, 
        get_default_ocr_model, create_tesseract_model, create_paddle_ocr_model
    )
    from core.services.ocr_service import (
        OCRService, OCRQuality, create_ocr_service, 
        quick_ocr_text_extraction_sync
    )
    from core.processing.ocr_processor import (
        OCRProcessor, OCRProcessingConfig, DocumentType, 
        PreprocessingMode, create_ocr_processor, quick_document_ocr
    )
except ImportError as e:
    print(f"Failed to import OCR modules: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rich console for pretty output
console = Console()


class OCRDemoSuite:
    """Comprehensive OCR demonstration suite."""
    
    def __init__(self):
        self.console = console
        self.temp_dir = Path(tempfile.mkdtemp(prefix="ocr_demo_"))
        self.demo_results = {}
        
        # Check available engines
        self.available_engines = get_available_ocr_engines()
        if not self.available_engines:
            self.console.print("[red]❌ No OCR engines available![/red]")
            self.console.print("Please install Tesseract or PaddleOCR to run demos.")
            sys.exit(1)
            
        self.console.print(f"[green]✓ Found OCR engines: {[e.value for e in self.available_engines]}[/green]")
    
    def create_sample_documents(self) -> Dict[str, Path]:
        """Create sample documents for demonstration."""
        self.console.print("[blue]📄 Creating sample documents...[/blue]")
        
        documents = {}
        
        # 1. Simple text document
        simple_doc = self.temp_dir / "simple_document.png"
        img = Image.new('RGB', (600, 200), color='white')
        draw = ImageDraw.Draw(img)
        
        try:
            font = ImageFont.load_default()
        except:
            font = None
        
        draw.text((20, 30), "MEDICAL RECORD", fill='black', font=font)
        draw.text((20, 70), "Patient: John Smith", fill='black', font=font)
        draw.text((20, 100), "DOB: 01/15/1985", fill='black', font=font)
        draw.text((20, 130), "SSN: 123-45-6789", fill='black', font=font)
        draw.text((20, 160), "Phone: (555) 123-4567", fill='black', font=font)
        img.save(simple_doc)
        documents['simple'] = simple_doc
        
        # 2. Invoice document
        invoice_doc = self.temp_dir / "invoice_sample.png"
        img = Image.new('RGB', (800, 400), color='white')
        draw = ImageDraw.Draw(img)
        
        draw.rectangle([10, 10, 790, 390], outline='black', width=2)
        draw.text((50, 40), "INVOICE #INV-2024-001", fill='black', font=font)
        draw.text((50, 80), "Date: March 15, 2024", fill='black', font=font)
        draw.text((50, 120), "Bill To:", fill='black', font=font)
        draw.text((50, 150), "Jane Doe", fill='black', font=font)
        draw.text((50, 180), "123 Main Street", fill='black', font=font)
        draw.text((50, 210), "Anytown, ST 12345", fill='black', font=font)
        draw.text((50, 250), "Email: jane.doe@email.com", fill='black', font=font)
        draw.text((50, 290), "Credit Card: **** **** **** 1234", fill='black', font=font)
        draw.text((50, 330), "Total Amount: $1,234.56", fill='black', font=font)
        img.save(invoice_doc)
        documents['invoice'] = invoice_doc
        
        # 3. Low quality/noisy document
        noisy_doc = self.temp_dir / "noisy_document.png"
        img = Image.new('RGB', (500, 300), color='lightgray')
        draw = ImageDraw.Draw(img)
        
        # Add some noise
        for _ in range(1000):
            x, y = np.random.randint(0, 500), np.random.randint(0, 300)
            draw.point((x, y), fill='gray')
        
        draw.text((20, 50), "CONFIDENTIAL DOCUMENT", fill='darkblue', font=font)
        draw.text((20, 100), "Employee: Alice Johnson", fill='darkblue', font=font)
        draw.text((20, 130), "Employee ID: EMP-7890", fill='darkblue', font=font)
        draw.text((20, 160), "Salary: $75,000", fill='darkblue', font=font)
        draw.text((20, 190), "Bank Account: 987654321", fill='darkblue', font=font)
        img.save(noisy_doc)
        documents['noisy'] = noisy_doc
        
        # 4. Multi-language document
        multilang_doc = self.temp_dir / "multilang_document.png"
        img = Image.new('RGB', (600, 250), color='white')
        draw = ImageDraw.Draw(img)
        
        draw.text((20, 30), "INTERNATIONAL FORM", fill='black', font=font)
        draw.text((20, 70), "Name: María García", fill='black', font=font)
        draw.text((20, 100), "Nom: Jean Dupont", fill='black', font=font)
        draw.text((20, 130), "नाम: राम शर्मा", fill='black', font=font)
        draw.text((20, 160), "Phone: +1-555-987-6543", fill='black', font=font)
        draw.text((20, 190), "Email: info@example.com", fill='black', font=font)
        img.save(multilang_doc)
        documents['multilang'] = multilang_doc
        
        # 5. Table/structured data
        table_doc = self.temp_dir / "table_document.png"
        img = Image.new('RGB', (700, 350), color='white')
        draw = ImageDraw.Draw(img)
        
        # Draw table structure
        for i in range(0, 701, 175):  # Vertical lines
            draw.line([(i, 50), (i, 300)], fill='black', width=1)
        for i in range(50, 301, 50):  # Horizontal lines
            draw.line([(0, i), (700, i)], fill='black', width=1)
        
        # Table headers
        draw.text((10, 20), "EMPLOYEE DATA TABLE", fill='black', font=font)
        draw.text((20, 60), "Name", fill='black', font=font)
        draw.text((195, 60), "ID", fill='black', font=font)
        draw.text((370, 60), "Department", fill='black', font=font)
        draw.text((545, 60), "Salary", fill='black', font=font)
        
        # Table data
        employees = [
            ("Bob Wilson", "12345", "Engineering", "$85,000"),
            ("Carol Davis", "67890", "Marketing", "$65,000"),
            ("David Lee", "54321", "Finance", "$70,000"),
            ("Eva Brown", "98765", "HR", "$60,000")
        ]
        
        for i, (name, emp_id, dept, salary) in enumerate(employees):
            y = 110 + i * 50
            draw.text((20, y), name, fill='black', font=font)
            draw.text((195, y), emp_id, fill='black', font=font)
            draw.text((370, y), dept, fill='black', font=font)
            draw.text((545, y), salary, fill='black', font=font)
        
        img.save(table_doc)
        documents['table'] = table_doc
        
        self.console.print(f"[green]✓ Created {len(documents)} sample documents in {self.temp_dir}[/green]")
        return documents
    
    def demo_basic_ocr(self, documents: Dict[str, Path]):
        """Demonstrate basic OCR functionality."""
        self.console.print("\n[cyan]🔤 BASIC OCR DEMONSTRATION[/cyan]")
        
        # Use first available engine
        engine = self.available_engines[0]
        self.console.print(f"Using OCR engine: [bold]{engine.value}[/bold]")
        
        service = create_ocr_service(engine, enable_pii=False)
        
        try:
            results_table = Table(title="OCR Results")
            results_table.add_column("Document", style="cyan")
            results_table.add_column("Success", style="green")
            results_table.add_column("Confidence", style="yellow")
            results_table.add_column("Word Count", style="blue")
            results_table.add_column("Preview", style="white")
            
            for doc_name, doc_path in documents.items():
                try:
                    result = service.extract_text_from_image(doc_path, detect_pii=False)
                    
                    if result.ocr_result.success:
                        success_icon = "✅"
                        confidence = f"{result.ocr_result.confidence_score:.1f}%"
                        word_count = str(result.ocr_result.word_count)
                        preview = result.ocr_result.text_content[:50].replace('\n', ' ')
                        if len(result.ocr_result.text_content) > 50:
                            preview += "..."
                    else:
                        success_icon = "❌"
                        confidence = "0.0%"
                        word_count = "0"
                        preview = "Failed to extract text"
                    
                    results_table.add_row(
                        doc_name,
                        success_icon,
                        confidence,
                        word_count,
                        preview
                    )
                    
                except Exception as e:
                    results_table.add_row(
                        doc_name,
                        "❌",
                        "0.0%",
                        "0",
                        f"Error: {str(e)[:30]}..."
                    )
            
            self.console.print(results_table)
            
        finally:
            service.cleanup()
    
    def demo_pii_detection_integration(self, documents: Dict[str, Path]):
        """Demonstrate OCR with PII detection integration."""
        self.console.print("\n[red]🔒 OCR + PII DETECTION DEMONSTRATION[/red]")
        
        engine = self.available_engines[0]
        service = create_ocr_service(engine, enable_pii=True)
        
        try:
            for doc_name, doc_path in documents.items():
                self.console.print(f"\n[blue]Processing: {doc_name}[/blue]")
                
                try:
                    result = service.extract_text_from_image(doc_path, detect_pii=True)
                    
                    if result.ocr_result.success:
                        # Show extracted text
                        text_panel = Panel(
                            result.ocr_result.text_content,
                            title=f"Extracted Text (Confidence: {result.ocr_result.confidence_score:.1f}%)",
                            border_style="green"
                        )
                        self.console.print(text_panel)
                        
                        # Show PII detection results
                        if result.pii_detection_result:
                            if hasattr(result.pii_detection_result, 'entities') and result.pii_detection_result.entities:
                                pii_table = Table(title="PII Entities Found")
                                pii_table.add_column("Entity Type", style="red")
                                pii_table.add_column("Text", style="yellow")
                                pii_table.add_column("Confidence", style="green")
                                
                                for entity in result.pii_detection_result.entities:
                                    pii_table.add_row(
                                        entity.entity_type,
                                        entity.text,
                                        f"{getattr(entity, 'confidence_score', 0.0):.1f}%"
                                    )
                                
                                self.console.print(pii_table)
                            else:
                                self.console.print("[green]✓ No PII entities detected[/green]")
                        else:
                            self.console.print("[yellow]⚠ PII detection not available[/yellow]")
                    
                    else:
                        self.console.print(f"[red]❌ OCR failed: {result.ocr_result.processing_errors}[/red]")
                
                except Exception as e:
                    self.console.print(f"[red]Error processing {doc_name}: {e}[/red]")
        
        finally:
            service.cleanup()
    
    def demo_preprocessing_modes(self, documents: Dict[str, Path]):
        """Demonstrate different preprocessing modes."""
        self.console.print("\n[magenta]⚙️ PREPROCESSING MODES DEMONSTRATION[/magenta]")
        
        # Use the noisy document for this demo
        noisy_doc = documents.get('noisy')
        if not noisy_doc:
            self.console.print("[yellow]⚠ Noisy document not available[/yellow]")
            return
        
        engine = self.available_engines[0]
        
        results_table = Table(title="Preprocessing Mode Comparison")
        results_table.add_column("Mode", style="cyan")
        results_table.add_column("Success", style="green")
        results_table.add_column("Confidence", style="yellow")
        results_table.add_column("Word Count", style="blue")
        results_table.add_column("Processing Time", style="magenta")
        
        for mode in PreprocessingMode:
            config = OCRProcessingConfig(
                engine=engine,
                preprocessing_mode=mode,
                enable_pii_detection=False
            )
            
            processor = create_ocr_processor(config)
            
            try:
                start_time = time.time()
                result = processor.process_document(noisy_doc)
                processing_time = time.time() - start_time
                
                if result.success and result.ocr_result:
                    success_icon = "✅"
                    confidence = f"{result.ocr_result.overall_confidence:.1f}%"
                    word_count = str(result.ocr_result.word_count)
                else:
                    success_icon = "❌"
                    confidence = "0.0%"
                    word_count = "0"
                
                results_table.add_row(
                    mode.value,
                    success_icon,
                    confidence,
                    word_count,
                    f"{processing_time:.2f}s"
                )
                
            except Exception as e:
                results_table.add_row(
                    mode.value,
                    "❌",
                    "0.0%",
                    "0",
                    "Error"
                )
            
            finally:
                processor.cleanup()
        
        self.console.print(results_table)
    
    def demo_batch_processing(self, documents: Dict[str, Path]):
        """Demonstrate batch processing capabilities."""
        self.console.print("\n[green]📦 BATCH PROCESSING DEMONSTRATION[/green]")
        
        engine = self.available_engines[0]
        service = create_ocr_service(engine, enable_pii=False, max_workers=2)
        
        try:
            document_paths = list(documents.values())
            
            # Synchronous batch processing
            self.console.print("Running synchronous batch processing...")
            with Progress() as progress:
                task = progress.add_task("Processing documents...", total=len(document_paths))
                
                start_time = time.time()
                results = service.batch_process_images(document_paths)
                batch_time = time.time() - start_time
                
                progress.update(task, completed=len(document_paths))
            
            # Show results
            batch_table = Table(title="Batch Processing Results")
            batch_table.add_column("Document", style="cyan")
            batch_table.add_column("Status", style="green")
            batch_table.add_column("Text Length", style="blue")
            batch_table.add_column("Confidence", style="yellow")
            
            successful = 0
            total_chars = 0
            
            for i, result in enumerate(results):
                doc_name = list(documents.keys())[i] if i < len(documents) else f"doc_{i}"
                
                if result.ocr_result.success:
                    status = "✅ Success"
                    text_len = len(result.ocr_result.text_content)
                    confidence = f"{result.ocr_result.confidence_score:.1f}%"
                    successful += 1
                    total_chars += text_len
                else:
                    status = "❌ Failed"
                    text_len = 0
                    confidence = "0.0%"
                
                batch_table.add_row(
                    doc_name,
                    status,
                    str(text_len),
                    confidence
                )
            
            self.console.print(batch_table)
            
            # Summary
            summary_panel = Panel(
                f"Processed: {len(results)} documents\n"
                f"Successful: {successful}\n"
                f"Failed: {len(results) - successful}\n"
                f"Total processing time: {batch_time:.2f}s\n"
                f"Average per document: {batch_time/len(results):.2f}s\n"
                f"Total characters extracted: {total_chars}",
                title="Batch Processing Summary",
                border_style="green"
            )
            self.console.print(summary_panel)
            
        finally:
            service.cleanup()
    
    async def demo_async_processing(self, documents: Dict[str, Path]):
        """Demonstrate asynchronous processing."""
        self.console.print("\n[blue]⚡ ASYNC PROCESSING DEMONSTRATION[/blue]")
        
        engine = self.available_engines[0]
        service = create_ocr_service(engine, enable_pii=False)
        
        try:
            document_paths = list(documents.values())
            
            # Asynchronous batch processing
            self.console.print("Running asynchronous batch processing...")
            
            start_time = time.time()
            results = await service.batch_process_images_async(document_paths)
            async_time = time.time() - start_time
            
            # Compare with synchronous processing
            start_time = time.time()
            sync_results = service.batch_process_images(document_paths)
            sync_time = time.time() - start_time
            
            # Show comparison
            comparison_table = Table(title="Async vs Sync Processing")
            comparison_table.add_column("Method", style="cyan")
            comparison_table.add_column("Time", style="yellow")
            comparison_table.add_column("Documents", style="blue")
            comparison_table.add_column("Success Rate", style="green")
            
            async_success = sum(1 for r in results if r.ocr_result.success)
            sync_success = sum(1 for r in sync_results if r.ocr_result.success)
            
            comparison_table.add_row(
                "Asynchronous",
                f"{async_time:.2f}s",
                str(len(results)),
                f"{async_success/len(results)*100:.1f}%"
            )
            
            comparison_table.add_row(
                "Synchronous",
                f"{sync_time:.2f}s",
                str(len(sync_results)),
                f"{sync_success/len(sync_results)*100:.1f}%"
            )
            
            self.console.print(comparison_table)
            
            speedup = sync_time / async_time if async_time > 0 else 1.0
            self.console.print(f"\n[green]Async speedup: {speedup:.2f}x[/green]")
            
        finally:
            service.cleanup()
    
    def demo_engine_comparison(self, documents: Dict[str, Path]):
        """Compare different OCR engines."""
        self.console.print("\n[yellow]⚖️ OCR ENGINE COMPARISON[/yellow]")
        
        if len(self.available_engines) < 2:
            self.console.print("[yellow]⚠ Only one OCR engine available for comparison[/yellow]")
            # Still show results for the single engine
            engine = self.available_engines[0]
            self._show_engine_results(engine, documents)
            return
        
        # Compare all available engines
        comparison_results = {}
        
        for engine in self.available_engines:
            self.console.print(f"Testing {engine.value}...")
            comparison_results[engine] = self._test_engine_performance(engine, documents)
        
        # Create comparison table
        comp_table = Table(title="OCR Engine Performance Comparison")
        comp_table.add_column("Engine", style="cyan")
        comp_table.add_column("Success Rate", style="green")
        comp_table.add_column("Avg Confidence", style="yellow")
        comp_table.add_column("Avg Time", style="blue")
        comp_table.add_column("Total Words", style="magenta")
        
        for engine, results in comparison_results.items():
            comp_table.add_row(
                engine.value,
                f"{results['success_rate']:.1f}%",
                f"{results['avg_confidence']:.1f}%",
                f"{results['avg_time']:.2f}s",
                str(results['total_words'])
            )
        
        self.console.print(comp_table)
        
        # Show detailed results for best performing engine
        best_engine = max(comparison_results.keys(), 
                         key=lambda e: comparison_results[e]['success_rate'])
        self.console.print(f"\n[green]🏆 Best performing engine: {best_engine.value}[/green]")
    
    def _test_engine_performance(self, engine: OCREngine, documents: Dict[str, Path]) -> Dict[str, Any]:
        """Test performance of a specific OCR engine."""
        service = create_ocr_service(engine, enable_pii=False)
        
        results = {
            'success_count': 0,
            'total_confidence': 0.0,
            'total_time': 0.0,
            'total_words': 0,
            'document_count': len(documents)
        }
        
        try:
            for doc_path in documents.values():
                try:
                    start_time = time.time()
                    result = service.extract_text_from_image(doc_path, detect_pii=False)
                    processing_time = time.time() - start_time
                    
                    results['total_time'] += processing_time
                    
                    if result.ocr_result.success:
                        results['success_count'] += 1
                        results['total_confidence'] += result.ocr_result.confidence_score
                        results['total_words'] += result.ocr_result.word_count
                
                except Exception:
                    pass  # Count as failure
        
        finally:
            service.cleanup()
        
        # Calculate averages
        results['success_rate'] = (results['success_count'] / results['document_count']) * 100
        results['avg_confidence'] = results['total_confidence'] / max(results['success_count'], 1)
        results['avg_time'] = results['total_time'] / results['document_count']
        
        return results
    
    def _show_engine_results(self, engine: OCREngine, documents: Dict[str, Path]):
        """Show detailed results for a single engine."""
        service = create_ocr_service(engine, enable_pii=False)
        
        try:
            results_table = Table(title=f"Detailed Results - {engine.value}")
            results_table.add_column("Document", style="cyan")
            results_table.add_column("Status", style="green")
            results_table.add_column("Confidence", style="yellow")
            results_table.add_column("Words", style="blue")
            results_table.add_column("Time", style="magenta")
            
            for doc_name, doc_path in documents.items():
                try:
                    start_time = time.time()
                    result = service.extract_text_from_image(doc_path, detect_pii=False)
                    processing_time = time.time() - start_time
                    
                    if result.ocr_result.success:
                        status = "✅"
                        confidence = f"{result.ocr_result.confidence_score:.1f}%"
                        words = str(result.ocr_result.word_count)
                    else:
                        status = "❌"
                        confidence = "0.0%"
                        words = "0"
                    
                    results_table.add_row(
                        doc_name,
                        status,
                        confidence,
                        words,
                        f"{processing_time:.2f}s"
                    )
                
                except Exception:
                    results_table.add_row(doc_name, "❌", "0.0%", "0", "Error")
            
            self.console.print(results_table)
        
        finally:
            service.cleanup()
    
    def interactive_mode(self):
        """Run interactive OCR demonstration."""
        self.console.print("\n[bold cyan]🎯 INTERACTIVE OCR DEMONSTRATION[/bold cyan]")
        
        # Create sample documents
        documents = self.create_sample_documents()
        
        while True:
            self.console.print("\n[bold]Available Demonstrations:[/bold]")
            self.console.print("1. Basic OCR Text Extraction")
            self.console.print("2. OCR + PII Detection Integration")
            self.console.print("3. Preprocessing Modes Comparison")
            self.console.print("4. Batch Processing Demo")
            self.console.print("5. Async Processing Demo")
            self.console.print("6. OCR Engine Comparison")
            self.console.print("7. Custom Document Upload")
            self.console.print("8. Performance Benchmark")
            self.console.print("0. Exit")
            
            choice = Prompt.ask("Select demonstration", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])
            
            try:
                if choice == "0":
                    break
                elif choice == "1":
                    self.demo_basic_ocr(documents)
                elif choice == "2":
                    self.demo_pii_detection_integration(documents)
                elif choice == "3":
                    self.demo_preprocessing_modes(documents)
                elif choice == "4":
                    self.demo_batch_processing(documents)
                elif choice == "5":
                    asyncio.run(self.demo_async_processing(documents))
                elif choice == "6":
                    self.demo_engine_comparison(documents)
                elif choice == "7":
                    self.demo_custom_upload()
                elif choice == "8":
                    self.demo_performance_benchmark(documents)
                
                if choice != "0":
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Demo interrupted by user[/yellow]")
                break
            except Exception as e:
                self.console.print(f"\n[red]Error during demo: {e}[/red]")
                if Confirm.ask("Continue with other demos?"):
                    continue
                else:
                    break
    
    def demo_custom_upload(self):
        """Allow user to upload their own document."""
        self.console.print("\n[cyan]📁 CUSTOM DOCUMENT UPLOAD[/cyan]")
        
        file_path = Prompt.ask("Enter path to your document (image or PDF)")
        
        if not os.path.exists(file_path):
            self.console.print(f"[red]❌ File not found: {file_path}[/red]")
            return
        
        file_path = Path(file_path)
        
        # Get processing options
        engine_choice = Prompt.ask(
            "Choose OCR engine",
            choices=[e.value for e in self.available_engines],
            default=self.available_engines[0].value
        )
        
        enable_pii = Confirm.ask("Enable PII detection?", default=True)
        
        preprocessing = Prompt.ask(
            "Choose preprocessing mode",
            choices=[mode.value for mode in PreprocessingMode],
            default=PreprocessingMode.ENHANCED.value
        )
        
        # Process document
        engine = OCREngine(engine_choice)
        config = OCRProcessingConfig(
            engine=engine,
            preprocessing_mode=PreprocessingMode(preprocessing),
            enable_pii_detection=enable_pii
        )
        
        processor = create_ocr_processor(config)
        
        try:
            self.console.print(f"\n[blue]Processing: {file_path.name}[/blue]")
            
            with Progress() as progress:
                task = progress.add_task("Processing document...", total=1)
                
                result = processor.process_document(file_path)
                progress.update(task, completed=1)
            
            if result.success and result.ocr_result:
                # Show results
                self.console.print(f"[green]✅ Processing successful![/green]")
                
                # Document info
                info_panel = Panel(
                    f"Document Type: {result.document_type.value}\n"
                    f"Total Pages: {result.ocr_result.total_pages}\n"
                    f"Overall Confidence: {result.ocr_result.overall_confidence:.1f}%\n"
                    f"Word Count: {result.ocr_result.word_count}\n"
                    f"Character Count: {result.ocr_result.character_count}\n"
                    f"Processing Time: {result.processing_time:.2f}s\n"
                    f"Engine Used: {result.ocr_result.engine_used}",
                    title="Document Information",
                    border_style="blue"
                )
                self.console.print(info_panel)
                
                # Show extracted text
                if len(result.ocr_result.combined_text) <= 500:
                    text_content = result.ocr_result.combined_text
                else:
                    text_content = result.ocr_result.combined_text[:500] + "\n\n... (truncated)"
                
                text_panel = Panel(
                    text_content,
                    title="Extracted Text",
                    border_style="green"
                )
                self.console.print(text_panel)
                
                # Show PII results if enabled
                if enable_pii and result.ocr_result.pii_summary:
                    pii_panel = Panel(
                        json.dumps(result.ocr_result.pii_summary, indent=2),
                        title="PII Detection Summary",
                        border_style="red"
                    )
                    self.console.print(pii_panel)
            
            else:
                self.console.print(f"[red]❌ Processing failed: {result.processing_errors}[/red]")
        
        finally:
            processor.cleanup()
    
    def demo_performance_benchmark(self, documents: Dict[str, Path]):
        """Run performance benchmark."""
        self.console.print("\n[magenta]🏎️ PERFORMANCE BENCHMARK[/magenta]")
        
        iterations = int(Prompt.ask("Number of iterations per test", default="3"))
        
        benchmark_results = {}
        
        for engine in self.available_engines:
            self.console.print(f"\nBenchmarking {engine.value}...")
            
            service = create_ocr_service(engine, enable_pii=False)
            engine_times = []
            
            try:
                for i in range(iterations):
                    with Progress() as progress:
                        task = progress.add_task(f"Iteration {i+1}", total=len(documents))
                        
                        start_time = time.time()
                        for doc_path in documents.values():
                            try:
                                service.extract_text_from_image(doc_path, detect_pii=False)
                            except:
                                pass
                            progress.advance(task)
                        
                        iteration_time = time.time() - start_time
                        engine_times.append(iteration_time)
                
                benchmark_results[engine] = {
                    'avg_time': np.mean(engine_times),
                    'min_time': min(engine_times),
                    'max_time': max(engine_times),
                    'std_dev': np.std(engine_times)
                }
            
            finally:
                service.cleanup()
        
        # Show benchmark results
        benchmark_table = Table(title="Performance Benchmark Results")
        benchmark_table.add_column("Engine", style="cyan")
        benchmark_table.add_column("Avg Time", style="green")
        benchmark_table.add_column("Min Time", style="blue")
        benchmark_table.add_column("Max Time", style="red")
        benchmark_table.add_column("Std Dev", style="yellow")
        
        for engine, results in benchmark_results.items():
            benchmark_table.add_row(
                engine.value,
                f"{results['avg_time']:.2f}s",
                f"{results['min_time']:.2f}s",
                f"{results['max_time']:.2f}s",
                f"{results['std_dev']:.2f}s"
            )
        
        self.console.print(benchmark_table)
    
    def cleanup(self):
        """Clean up temporary files."""
        try:
            import shutil
            shutil.rmtree(self.temp_dir)
            self.console.print(f"[green]✓ Cleaned up temporary directory: {self.temp_dir}[/green]")
        except Exception as e:
            self.console.print(f"[yellow]⚠ Cleanup warning: {e}[/yellow]")


def main():
    """Main demonstration function."""
    parser = argparse.ArgumentParser(
        description="OCR Detection Demonstration Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python demo_ocr_detection.py --mode interactive
    python demo_ocr_detection.py --mode batch --input ./documents/
    python demo_ocr_detection.py --mode benchmark
        """
    )
    
    parser.add_argument(
        "--mode", 
        choices=["interactive", "batch", "benchmark", "quick"],
        default="interactive",
        help="Demonstration mode"
    )
    
    parser.add_argument(
        "--engine",
        choices=["tesseract", "paddle"],
        help="OCR engine to use (if available)"
    )
    
    parser.add_argument(
        "--input",
        help="Input directory or file for batch processing"
    )
    
    parser.add_argument(
        "--output",
        help="Output directory for results"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize demo suite
    demo = OCRDemoSuite()
    
    try:
        console.print(Panel(
            Text("OCR Detection System Demonstration", style="bold cyan", justify="center"),
            border_style="cyan"
        ))
        
        console.print(f"Available OCR engines: {[e.value for e in demo.available_engines]}")
        
        if args.mode == "interactive":
            demo.interactive_mode()
        
        elif args.mode == "batch":
            if args.input:
                input_path = Path(args.input)
                if input_path.is_dir():
                    # Find image and PDF files in directory
                    supported_exts = {'.png', '.jpg', '.jpeg', '.tiff', '.pdf', '.bmp'}
                    files = [f for f in input_path.rglob('*') if f.suffix.lower() in supported_exts]
                    
                    if files:
                        console.print(f"Found {len(files)} files for processing")
                        # Process files in batches
                        # Implementation would go here
                    else:
                        console.print("[red]No supported files found in directory[/red]")
                else:
                    console.print("[red]Input path is not a directory[/red]")
            else:
                # Create sample documents and run batch demo
                documents = demo.create_sample_documents()
                demo.demo_batch_processing(documents)
        
        elif args.mode == "benchmark":
            documents = demo.create_sample_documents()
            demo.demo_performance_benchmark(documents)
        
        elif args.mode == "quick":
            # Quick demo with basic functionality
            documents = demo.create_sample_documents()
            demo.demo_basic_ocr(documents)
        
        console.print("\n[green]🎉 Demonstration completed successfully![/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Demonstration interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Demonstration failed: {e}[/red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
    finally:
        demo.cleanup()


if __name__ == "__main__":
    main()