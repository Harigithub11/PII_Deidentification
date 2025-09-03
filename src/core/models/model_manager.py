"""
Model Manager for PII De-identification System

This module provides centralized management of AI models with memory-efficient
loading/unloading and caching strategies.
"""

import os
import gc
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from contextlib import contextmanager
import torch
import psutil

from ..config.settings import get_settings
from ..config.model_config import get_model_config

logger = logging.getLogger(__name__)


class ModelManager:
    """Central manager for AI models with memory optimization."""
    
    def __init__(self):
        self.settings = get_settings()
        self.model_config = get_model_config()
        
        # Model instances
        self._models: Dict[str, Any] = {}
        self._model_states: Dict[str, Dict[str, Any]] = {}
        
        # Memory management
        self.max_gpu_memory_mb = self.settings.max_gpu_memory_mb
        self.current_gpu_memory_mb = 0
        self.model_memory_usage: Dict[str, int] = {}
        
        # Initialize paths
        self._setup_model_paths()
        
        logger.info(f"ModelManager initialized with GPU memory limit: {self.max_gpu_memory_mb}MB")
    
    def _setup_model_paths(self):
        """Setup model directory paths."""
        self.model_paths = self.model_config.get_model_paths()
        
        # Create directories if they don't exist
        for path in self.model_paths.values():
            path.mkdir(parents=True, exist_ok=True)
        
        logger.info("Model paths initialized")
    
    def get_model(self, model_name: str, force_reload: bool = False) -> Any:
        """Get a model instance, loading if necessary."""
        if model_name in self._models and not force_reload:
            return self._models[model_name]
        
        # Check memory constraints
        if not self._check_memory_constraints(model_name):
            self._unload_least_used_model()
        
        # Load the model
        model = self._load_model(model_name)
        if model is not None:
            self._models[model_name] = model
            self._update_memory_usage(model_name)
            logger.info(f"Model {model_name} loaded successfully")
        
        return model
    
    def _load_model(self, model_name: str) -> Any:
        """Load a specific model."""
        try:
            if model_name == "tesseract":
                return self._load_tesseract_model()
            elif model_name == "spacy":
                return self._load_spacy_model()
            elif model_name == "layoutlm":
                return self._load_layoutlm_model()
            elif model_name == "yolo":
                return self._load_yolo_model()
            elif model_name == "mistral":
                return self._load_mistral_model()
            else:
                logger.error(f"Unknown model: {model_name}")
                return None
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            return None
    
    def _load_tesseract_model(self):
        """Load Tesseract OCR model."""
        try:
            import pytesseract
            # Configure Tesseract
            pytesseract.pytesseract.tesseract_cmd = self._find_tesseract_binary()
            return pytesseract
        except ImportError:
            logger.error("pytesseract not installed")
            return None
    
    def _load_spacy_model(self):
        """Load spaCy NER model."""
        try:
            import spacy
            model_name = self.model_config.ner.spacy_model
            model_path = self.model_paths['spacy'] / model_name
            
            if model_path.exists():
                return spacy.load(str(model_path))
            else:
                # Download if not available
                return spacy.load(model_name)
        except Exception as e:
            logger.error(f"Failed to load spaCy model: {e}")
            return None
    
    def _load_layoutlm_model(self):
        """Load LayoutLMv3 model."""
        try:
            from transformers import LayoutLMv3Processor, LayoutLMv3ForSequenceClassification
            
            model_name = self.model_config.layout.layoutlm_model
            processor = LayoutLMv3Processor.from_pretrained(model_name)
            model = LayoutLMv3ForSequenceClassification.from_pretrained(model_name)
            
            # Move to appropriate device
            device = self._get_device()
            model = model.to(device)
            
            return {"processor": processor, "model": model}
        except Exception as e:
            logger.error(f"Failed to load LayoutLM model: {e}")
            return None
    
    def _load_yolo_model(self):
        """Load YOLOv8 model."""
        try:
            from ultralytics import YOLO
            
            model_name = self.model_config.visual.yolo_model
            model_path = self.model_paths['yolo'] / model_name
            
            if model_path.exists():
                model = YOLO(str(model_path))
            else:
                model = YOLO(model_name)
            
            # Move to appropriate device
            device = self._get_device()
            model.to(device)
            
            return model
        except Exception as e:
            logger.error(f"Failed to load YOLO model: {e}")
            return None
    
    def _load_mistral_model(self):
        """Load Mistral 7B model."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            
            model_name = self.model_config.llm.model_name
            model_path = self.model_config.llm.model_path
            
            if model_path and Path(model_path).exists():
                tokenizer = AutoTokenizer.from_pretrained(model_path)
                model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    torch_dtype=torch.float16,
                    device_map="auto" if self.settings.is_gpu_available() else None
                )
            else:
                tokenizer = AutoTokenizer.from_pretrained(model_name)
                model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    torch_dtype=torch.float16,
                    device_map="auto" if self.settings.is_gpu_available() else None
                )
            
            return {"tokenizer": tokenizer, "model": model}
        except Exception as e:
            logger.error(f"Failed to load Mistral model: {e}")
            return None
    
    def _find_tesseract_binary(self) -> str:
        """Find Tesseract binary path."""
        # Common paths
        common_paths = [
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",  # Windows
            "/usr/bin/tesseract",  # Linux
            "/usr/local/bin/tesseract",  # macOS
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Try to find in PATH
        import shutil
        tesseract_path = shutil.which("tesseract")
        if tesseract_path:
            return tesseract_path
        
        raise FileNotFoundError("Tesseract binary not found")
    
    def _get_device(self) -> str:
        """Get the appropriate device for models."""
        if self.settings.is_gpu_available():
            return "cuda"
        return "cpu"
    
    def _check_memory_constraints(self, model_name: str) -> bool:
        """Check if there's enough memory to load a model."""
        if not self.settings.is_gpu_available():
            return True  # CPU mode, no GPU memory constraints
        
        # Estimate model memory usage
        estimated_memory = self._estimate_model_memory(model_name)
        available_memory = self.max_gpu_memory_mb - self.current_gpu_memory_mb
        
        return estimated_memory <= available_memory
    
    def _estimate_model_memory(self, model_name: str) -> int:
        """Estimate memory usage for a model (in MB)."""
        memory_estimates = {
            "tesseract": 100,      # ~100MB
            "spacy": 500,          # ~500MB
            "layoutlm": 1000,      # ~1GB
            "yolo": 800,           # ~800MB
            "mistral": 4000,       # ~4GB (quantized)
        }
        
        return memory_estimates.get(model_name, 1000)
    
    def _unload_least_used_model(self):
        """Unload the least recently used model to free memory."""
        if not self._models:
            return
        
        # Find least used model
        least_used = min(self._models.keys(), key=lambda k: self._model_states.get(k, {}).get('last_used', 0))
        
        logger.info(f"Unloading least used model: {least_used}")
        self.unload_model(least_used)
    
    def unload_model(self, model_name: str):
        """Unload a specific model."""
        if model_name not in self._models:
            return
        
        # Save model state if needed
        self._save_model_state(model_name)
        
        # Remove model from memory
        del self._models[model_name]
        
        # Update memory usage
        if model_name in self.model_memory_usage:
            self.current_gpu_memory_mb -= self.model_memory_usage[model_name]
            del self.model_memory_usage[model_name]
        
        # Force garbage collection
        gc.collect()
        if self.settings.is_gpu_available():
            torch.cuda.empty_cache()
        
        logger.info(f"Model {model_name} unloaded")
    
    def _save_model_state(self, model_name: str):
        """Save model state for later restoration."""
        if model_name in self._models:
            # Save any necessary state information
            self._model_states[model_name] = {
                'last_used': self._get_current_time(),
                'memory_usage': self.model_memory_usage.get(model_name, 0)
            }
    
    def _update_memory_usage(self, model_name: str):
        """Update memory usage tracking."""
        if self.settings.is_gpu_available():
            estimated_memory = self._estimate_model_memory(model_name)
            self.model_memory_usage[model_name] = estimated_memory
            self.current_gpu_memory_mb += estimated_memory
    
    def _get_current_time(self) -> float:
        """Get current timestamp."""
        import time
        return time.time()
    
    def get_loaded_models(self) -> List[str]:
        """Get list of currently loaded models."""
        return list(self._models.keys())
    
    def get_memory_usage(self) -> Dict[str, Any]:
        """Get current memory usage information."""
        memory_info = {
            'gpu_memory': {
                'total_mb': self.max_gpu_memory_mb,
                'used_mb': self.current_gpu_memory_mb,
                'available_mb': self.max_gpu_memory_mb - self.current_gpu_memory_mb
            },
            'model_memory': self.model_memory_usage.copy(),
            'system_memory': {
                'total_gb': psutil.virtual_memory().total / (1024**3),
                'available_gb': psutil.virtual_memory().available / (1024**3),
                'percent_used': psutil.virtual_memory().percent
            }
        }
        
        return memory_info
    
    def preload_models(self, model_names: List[str]):
        """Preload specified models."""
        for model_name in model_names:
            try:
                self.get_model(model_name)
                logger.info(f"Model {model_name} preloaded successfully")
            except Exception as e:
                logger.error(f"Failed to preload model {model_name}: {e}")
    
    def unload_all_models(self):
        """Unload all models."""
        model_names = list(self._models.keys())
        for model_name in model_names:
            self.unload_model(model_name)
        
        logger.info("All models unloaded")
    
    @contextmanager
    def model_context(self, model_name: str):
        """Context manager for model usage."""
        model = self.get_model(model_name)
        try:
            yield model
        finally:
            # Update last used time
            if model_name in self._model_states:
                self._model_states[model_name]['last_used'] = self._get_current_time()
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on all models."""
        health_status = {
            'status': 'healthy',
            'models': {},
            'memory': self.get_memory_usage(),
            'errors': []
        }
        
        for model_name in self._models:
            try:
                # Basic health check for each model
                model = self._models[model_name]
                health_status['models'][model_name] = {
                    'status': 'healthy',
                    'loaded': True,
                    'memory_mb': self.model_memory_usage.get(model_name, 0)
                }
            except Exception as e:
                health_status['models'][model_name] = {
                    'status': 'unhealthy',
                    'loaded': False,
                    'error': str(e)
                }
                health_status['errors'].append(f"Model {model_name}: {e}")
                health_status['status'] = 'unhealthy'
        
        return health_status


# Global model manager instance
model_manager = ModelManager()


def get_model_manager() -> ModelManager:
    """Get the global model manager instance."""
    return model_manager
