#!/usr/bin/env python3
"""
Model Installation Script for PII De-identification System

This script downloads and sets up all required AI models for the system.
"""

import os
import sys
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Any

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from core.config.settings import get_settings
from core.config.model_config import get_model_config

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ModelInstaller:
    """Handles installation and setup of AI models."""
    
    def __init__(self):
        self.settings = get_settings()
        self.model_config = get_model_config()
        self.model_paths = self.model_config.get_model_paths()
        
        # Model download URLs and configurations
        self.model_downloads = {
            "spacy": {
                "models": ["en_core_web_lg", "hi_core_news_sm"],
                "commands": [
                    "python -m spacy download en_core_web_lg",
                    "python -m spacy download hi_core_news_sm"
                ]
            },
            "transformers": {
                "models": [
                    "microsoft/layoutlmv3-base",
                    "mistralai/Mistral-7B-Instruct-v0.1"
                ],
                "cache_dir": str(self.model_paths['transformers'])
            },
            "yolo": {
                "models": ["yolov8n.pt", "yolov8s.pt"],
                "download_script": "from ultralytics import YOLO; YOLO('yolov8n.pt'); YOLO('yolov8s.pt')"
            }
        }
    
    def install_all_models(self):
        """Install all required models."""
        logger.info("Starting model installation...")
        
        try:
            # Create necessary directories
            self._create_directories()
            
            # Install spaCy models
            self._install_spacy_models()
            
            # Download transformer models
            self._download_transformer_models()
            
            # Download YOLO models
            self._download_yolo_models()
            
            # Verify installations
            self._verify_installations()
            
            logger.info("All models installed successfully!")
            
        except Exception as e:
            logger.error(f"Model installation failed: {e}")
            sys.exit(1)
    
    def _create_directories(self):
        """Create necessary directories."""
        logger.info("Creating model directories...")
        
        for path_name, path in self.model_paths.items():
            path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {path}")
    
    def _install_spacy_models(self):
        """Install spaCy language models."""
        logger.info("Installing spaCy models...")
        
        for command in self.model_downloads["spacy"]["commands"]:
            try:
                logger.info(f"Running: {command}")
                result = subprocess.run(
                    command.split(),
                    capture_output=True,
                    text=True,
                    check=True
                )
                logger.info(f"Successfully installed spaCy model")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install spaCy model: {e}")
                logger.error(f"Error output: {e.stderr}")
                raise
    
    def _download_transformer_models(self):
        """Download transformer models."""
        logger.info("Downloading transformer models...")
        
        # Set environment variables for transformers cache
        os.environ['TRANSFORMERS_CACHE'] = self.model_downloads["transformers"]["cache_dir"]
        os.environ['HF_HOME'] = self.model_downloads["transformers"]["cache_dir"]
        
        for model_name in self.model_downloads["transformers"]["models"]:
            try:
                logger.info(f"Downloading model: {model_name}")
                
                # Use Python script to download
                download_script = f"""
import torch
from transformers import AutoTokenizer, AutoModel

# Download tokenizer
tokenizer = AutoTokenizer.from_pretrained("{model_name}")
tokenizer.save_pretrained("{self.model_paths['transformers'] / model_name.split('/')[-1]}")

# Download model (with quantization for large models)
if "mistral" in "{model_name}".lower():
    model = AutoModel.from_pretrained("{model_name}", torch_dtype=torch.float16)
else:
    model = AutoModel.from_pretrained("{model_name}")

model.save_pretrained("{self.model_paths['transformers'] / model_name.split('/')[-1]}")
print(f"Model {model_name} downloaded successfully")
"""
                
                result = subprocess.run(
                    [sys.executable, "-c", download_script],
                    capture_output=True,
                    text=True,
                    check=True
                )
                logger.info(f"Successfully downloaded: {model_name}")
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to download model {model_name}: {e}")
                logger.error(f"Error output: {e.stderr}")
                raise
    
    def _download_yolo_models(self):
        """Download YOLO models."""
        logger.info("Downloading YOLO models...")
        
        try:
            download_script = self.model_downloads["yolo"]["download_script"]
            
            result = subprocess.run(
                [sys.executable, "-c", download_script],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Successfully downloaded YOLO models")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to download YOLO models: {e}")
            logger.error(f"Error output: {e.stderr}")
            raise
    
    def _verify_installations(self):
        """Verify that all models are properly installed."""
        logger.info("Verifying model installations...")
        
        verification_results = {
            "spacy": self._verify_spacy_models(),
            "transformers": self._verify_transformer_models(),
            "yolo": self._verify_yolo_models()
        }
        
        all_verified = all(verification_results.values())
        
        if all_verified:
            logger.info("All model verifications passed!")
        else:
            failed_models = [k for k, v in verification_results.items() if not v]
            logger.error(f"Model verification failed for: {failed_models}")
            raise Exception("Model verification failed")
    
    def _verify_spacy_models(self) -> bool:
        """Verify spaCy models installation."""
        try:
            import spacy
            
            for model_name in self.model_downloads["spacy"]["models"]:
                try:
                    nlp = spacy.load(model_name)
                    logger.info(f"✓ spaCy model {model_name} verified")
                except OSError:
                    logger.error(f"✗ spaCy model {model_name} not found")
                    return False
            
            return True
            
        except ImportError:
            logger.error("spaCy not installed")
            return False
    
    def _verify_transformer_models(self) -> bool:
        """Verify transformer models installation."""
        try:
            from transformers import AutoTokenizer, AutoModel
            
            for model_name in self.model_downloads["transformers"]["models"]:
                model_short_name = model_name.split('/')[-1]
                model_path = self.model_paths['transformers'] / model_short_name
                
                if model_path.exists():
                    try:
                        # Try to load the model
                        tokenizer = AutoTokenizer.from_pretrained(str(model_path))
                        model = AutoModel.from_pretrained(str(model_path))
                        logger.info(f"✓ Transformer model {model_short_name} verified")
                    except Exception as e:
                        logger.error(f"✗ Failed to load transformer model {model_short_name}: {e}")
                        return False
                else:
                    logger.error(f"✗ Transformer model {model_short_name} not found at {model_path}")
                    return False
            
            return True
            
        except ImportError:
            logger.error("Transformers library not installed")
            return False
    
    def _verify_yolo_models(self) -> bool:
        """Verify YOLO models installation."""
        try:
            from ultralytics import YOLO
            
            # Check if models can be loaded
            yolo_n = YOLO('yolov8n.pt')
            yolo_s = YOLO('yolov8s.pt')
            
            logger.info("✓ YOLO models verified")
            return True
            
        except ImportError:
            logger.error("Ultralytics library not installed")
            return False
        except Exception as e:
            logger.error(f"Failed to verify YOLO models: {e}")
            return False
    
    def get_installation_summary(self) -> Dict[str, Any]:
        """Get summary of installed models."""
        summary = {
            "spacy_models": [],
            "transformer_models": [],
            "yolo_models": [],
            "total_size_mb": 0
        }
        
        # Check spaCy models
        try:
            import spacy
            for model_name in self.model_downloads["spacy"]["models"]:
                try:
                    nlp = spacy.load(model_name)
                    summary["spacy_models"].append(model_name)
                except OSError:
                    pass
        except ImportError:
            pass
        
        # Check transformer models
        for model_name in self.model_downloads["transformers"]["models"]:
            model_short_name = model_name.split('/')[-1]
            model_path = self.model_paths['transformers'] / model_short_name
            if model_path.exists():
                summary["transformer_models"].append(model_short_name)
        
        # Check YOLO models
        try:
            from ultralytics import YOLO
            summary["yolo_models"] = ["yolov8n.pt", "yolov8s.pt"]
        except ImportError:
            pass
        
        return summary


def main():
    """Main function for model installation."""
    print("=" * 60)
    print("PII De-identification System - Model Installation")
    print("=" * 60)
    
    installer = ModelInstaller()
    
    try:
        installer.install_all_models()
        
        # Print summary
        summary = installer.get_installation_summary()
        print("\n" + "=" * 60)
        print("Installation Summary:")
        print("=" * 60)
        print(f"✓ spaCy Models: {', '.join(summary['spacy_models'])}")
        print(f"✓ Transformer Models: {', '.join(summary['transformer_models'])}")
        print(f"✓ YOLO Models: {', '.join(summary['yolo_models'])}")
        print("\nAll models installed successfully!")
        
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        print("Please check the error messages above and try again.")
        sys.exit(1)


if __name__ == "__main__":
    main()
