"""
Model-specific configuration for PII De-identification System

This module provides configuration for different AI/ML models used in the system.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional, Union
from pydantic import BaseModel, Field


class OCRModelConfig(BaseModel):
    """Configuration for OCR models."""
    
    # Tesseract Configuration
    tesseract_languages: List[str] = Field(default=["eng", "hin"])
    tesseract_config: str = Field(default="--oem 3 --psm 6")
    tesseract_timeout: int = Field(default=30)
    
    # PaddleOCR Configuration
    paddleocr_use_gpu: bool = Field(default=True)
    paddleocr_lang: str = Field(default="en")
    paddleocr_use_angle_cls: bool = Field(default=True)
    paddleocr_use_gpu_cls: bool = Field(default=True)
    
    # General OCR Settings
    confidence_threshold: float = Field(default=0.7)
    max_image_size: int = Field(default=4096)
    supported_formats: List[str] = Field(default=["png", "jpg", "jpeg", "tiff", "tif", "bmp"])


class NERModelConfig(BaseModel):
    """Configuration for Named Entity Recognition models."""
    
    # spaCy Configuration
    spacy_model: str = Field(default="en_core_web_lg")
    spacy_entities: List[str] = Field(default=[
        "PERSON", "ORG", "GPE", "LOC", "FAC", "PRODUCT", "EVENT", "WORK_OF_ART", "LAW", "LANGUAGE"
    ])
    
    # Presidio Configuration
    presidio_analyzer_entities: List[str] = Field(default=[
        "PHONE_NUMBER", "EMAIL_ADDRESS", "CREDIT_CARD", "IBAN_CODE", "IP_ADDRESS",
        "LOCATION", "DATE_TIME", "NRP", "MEDICAL_LICENSE", "US_SSN", "US_PASSPORT",
        "US_DRIVER_LICENSE", "CRYPTO", "US_BANK_NUMBER", "US_ITIN", "US_DEA"
    ])
    
    # Custom NER Configuration
    custom_ner_enabled: bool = Field(default=True)
    custom_ner_model_path: Optional[str] = Field(default=None)
    custom_ner_threshold: float = Field(default=0.8)
    
    # Indian-specific PII patterns
    indian_patterns: Dict[str, str] = Field(default={
        "AADHAR": r"\b\d{4}\s\d{4}\s\d{4}\b",
        "PAN": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "MOBILE": r"\b[6-9]\d{9}\b",
        "PINCODE": r"\b[1-9][0-9]{5}\b"
    })


class LayoutModelConfig(BaseModel):
    """Configuration for document layout analysis models."""
    
    # LayoutLMv3 Configuration
    layoutlm_model: str = Field(default="microsoft/layoutlmv3-base")
    layoutlm_max_length: int = Field(default=512)
    layoutlm_confidence_threshold: float = Field(default=0.8)
    
    # Table Detection
    table_detection_enabled: bool = Field(default=True)
    table_detection_confidence: float = Field(default=0.7)
    
    # Form Field Detection
    form_detection_enabled: bool = Field(default=True)
    form_field_types: List[str] = Field(default=[
        "text_input", "checkbox", "radio", "dropdown", "signature", "date"
    ])


class VisualModelConfig(BaseModel):
    """Configuration for visual PII detection models."""
    
    # YOLOv8 Configuration
    yolo_model: str = Field(default="yolov8n.pt")
    yolo_confidence: float = Field(default=0.5)
    yolo_iou_threshold: float = Field(default=0.45)
    
    # Detection Classes
    detection_classes: List[str] = Field(default=[
        "face", "signature", "stamp", "seal", "qr_code", "barcode", "logo"
    ])
    
    # Image Processing
    max_image_dimension: int = Field(default=1024)
    preprocessing_enabled: bool = Field(default=True)
    augmentation_enabled: bool = Field(default=False)


class LLMModelConfig(BaseModel):
    """Configuration for Large Language Models (Mistral)."""
    
    # Mistral Configuration
    model_name: str = Field(default="mistral:7b-instruct")
    model_path: Optional[str] = Field(default=None)
    
    # Generation Parameters
    max_tokens: int = Field(default=512)
    temperature: float = Field(default=0.1)
    top_p: float = Field(default=0.9)
    top_k: int = Field(default=50)
    
    # Context and Memory
    max_context_length: int = Field(default=4096)
    enable_attention_sinks: bool = Field(default=True)
    
    # Performance
    use_quantization: bool = Field(default=True)
    quantization_bits: int = Field(default=4)
    enable_flash_attention: bool = Field(default=True)
    
    # Prompt Templates
    pii_analysis_prompt: str = Field(default="""
    Analyze the following text and identify any Personally Identifiable Information (PII):
    
    Text: {text}
    
    Please identify and classify any PII found, including:
    - Names (people, organizations)
    - Contact information (phone, email, address)
    - Identification numbers (SSN, passport, license)
    - Financial information (account numbers, credit cards)
    - Medical information
    - Any other sensitive personal data
    
    Format your response as JSON with the structure:
    {{
        "pii_detected": true/false,
        "entities": [
            {{
                "text": "extracted text",
                "type": "entity type",
                "confidence": 0.0-1.0,
                "start_pos": 0,
                "end_pos": 0
            }}
        ]
    }}
    """)


class ModelConfig(BaseModel):
    """Main model configuration container."""
    
    ocr: OCRModelConfig = Field(default_factory=OCRModelConfig)
    ner: NERModelConfig = Field(default_factory=NERModelConfig)
    layout: LayoutModelConfig = Field(default_factory=LayoutModelConfig)
    visual: VisualModelConfig = Field(default_factory=VisualModelConfig)
    llm: LLMModelConfig = Field(default_factory=LLMModelConfig)
    
    # Global Model Settings
    enable_gpu: bool = Field(default=True)
    max_gpu_memory_mb: int = Field(default=6000)
    model_device: str = Field(default="cuda")
    
    # Caching and Storage
    enable_model_caching: bool = Field(default=True)
    cache_dir: str = Field(default="./models/cache")
    download_dir: str = Field(default="./models/downloads")
    
    # Performance
    batch_size: int = Field(default=1)
    num_workers: int = Field(default=0)
    enable_parallel_processing: bool = Field(default=False)
    
    def get_model_paths(self) -> Dict[str, Path]:
        """Get all model-related paths."""
        base_path = Path(self.download_dir)
        return {
            'cache': Path(self.cache_dir),
            'downloads': base_path,
            'tesseract': base_path / 'tesseract',
            'spacy': base_path / 'spacy',
            'transformers': base_path / 'transformers',
            'yolo': base_path / 'yolo',
            'custom': base_path / 'custom',
        }
    
    def validate_configuration(self) -> bool:
        """Validate the model configuration."""
        try:
            # Check if required directories exist
            for path in self.get_model_paths().values():
                path.mkdir(parents=True, exist_ok=True)
            
            # Validate device setting
            if self.model_device not in ['cpu', 'cuda', 'mps']:
                raise ValueError(f"Invalid model device: {self.model_device}")
            
            # Validate GPU memory
            if self.max_gpu_memory_mb <= 0:
                raise ValueError("GPU memory must be positive")
            
            return True
        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False


# Global model configuration instance
model_config = ModelConfig()


def get_model_config() -> ModelConfig:
    """Get the global model configuration instance."""
    return model_config
