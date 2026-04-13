"""
Configuration management for AI De-identification System
Handles environment variables, file size limits, and system settings
"""
import os
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
import json
import logging

logger = logging.getLogger(__name__)

@dataclass
class FileSizeLimits:
    """File size limits configuration"""
    # Basic limits (in bytes)
    default_upload_limit: int = 10 * 1024 * 1024  # 10MB
    pdf_max_size: int = 100 * 1024 * 1024         # 100MB
    image_max_size: int = 50 * 1024 * 1024        # 50MB
    text_max_size: int = 10 * 1024 * 1024         # 10MB
    docx_max_size: int = 25 * 1024 * 1024         # 25MB
    
    # Premium user limits
    premium_upload_limit: int = 50 * 1024 * 1024   # 50MB
    premium_pdf_max_size: int = 500 * 1024 * 1024  # 500MB
    premium_image_max_size: int = 200 * 1024 * 1024 # 200MB
    
    # System limits
    absolute_max_size: int = 1024 * 1024 * 1024    # 1GB (safety limit)
    
    def to_mb(self, size_bytes: int) -> float:
        """Convert bytes to MB"""
        return size_bytes / (1024 * 1024)
    
    def get_limit_for_user(self, user_tier: str, file_type: str) -> int:
        """Get appropriate limit based on user tier and file type"""
        is_premium = user_tier in ['premium', 'enterprise']
        
        limits = {
            'pdf': self.premium_pdf_max_size if is_premium else self.pdf_max_size,
            'image': self.premium_image_max_size if is_premium else self.image_max_size,
            'text': self.text_max_size,  # Same for all users
            'docx': self.docx_max_size,  # Same for all users
            'default': self.premium_upload_limit if is_premium else self.default_upload_limit
        }
        
        return min(limits.get(file_type, limits['default']), self.absolute_max_size)

@dataclass
class ProcessingLimits:
    """Processing performance limits"""
    max_pdf_pages: int = 1000
    max_text_length: int = 100000
    max_concurrent_jobs: int = 5
    processing_timeout_seconds: int = 300
    
    # Premium limits
    premium_max_pdf_pages: int = 5000
    premium_max_text_length: int = 500000
    premium_max_concurrent_jobs: int = 20
    premium_processing_timeout: int = 1800
    
    def get_limit_for_user(self, user_tier: str, limit_type: str) -> int:
        """Get processing limit based on user tier"""
        is_premium = user_tier in ['premium', 'enterprise']
        
        limits = {
            'pdf_pages': self.premium_max_pdf_pages if is_premium else self.max_pdf_pages,
            'text_length': self.premium_max_text_length if is_premium else self.max_text_length,
            'concurrent_jobs': self.premium_max_concurrent_jobs if is_premium else self.max_concurrent_jobs,
            'timeout': self.premium_processing_timeout if is_premium else self.processing_timeout_seconds
        }
        
        return limits.get(limit_type, limits['timeout'])

@dataclass
class SystemConfig:
    """Main system configuration"""
    file_size_limits: FileSizeLimits = field(default_factory=FileSizeLimits)
    processing_limits: ProcessingLimits = field(default_factory=ProcessingLimits)
    
    # Database settings
    database_url: str = "sqlite:///./enterprise_deidentification.db"
    
    # Security settings
    secret_key: str = "your-secret-key-change-this-in-production"
    access_token_expire_minutes: int = 30
    
    # Feature flags
    enable_ocr: bool = True
    enable_magic_detection: bool = True
    enable_premium_features: bool = True
    debug_mode: bool = False
    
    # Logging settings
    log_level: str = "INFO"
    log_to_file: bool = False
    log_file_path: str = "./logs/system.log"
    
    @classmethod
    def from_env(cls) -> 'SystemConfig':
        """Load configuration from environment variables"""
        config = cls()
        
        # File size limits (in MB, converted to bytes)
        if os.getenv('DEFAULT_UPLOAD_LIMIT_MB'):
            config.file_size_limits.default_upload_limit = int(os.getenv('DEFAULT_UPLOAD_LIMIT_MB')) * 1024 * 1024
        
        if os.getenv('PDF_MAX_SIZE_MB'):
            config.file_size_limits.pdf_max_size = int(os.getenv('PDF_MAX_SIZE_MB')) * 1024 * 1024
        
        if os.getenv('IMAGE_MAX_SIZE_MB'):
            config.file_size_limits.image_max_size = int(os.getenv('IMAGE_MAX_SIZE_MB')) * 1024 * 1024
        
        # Processing limits
        if os.getenv('MAX_PDF_PAGES'):
            config.processing_limits.max_pdf_pages = int(os.getenv('MAX_PDF_PAGES'))
        
        if os.getenv('PROCESSING_TIMEOUT'):
            config.processing_limits.processing_timeout_seconds = int(os.getenv('PROCESSING_TIMEOUT'))
        
        # Database
        if os.getenv('DATABASE_URL'):
            config.database_url = os.getenv('DATABASE_URL')
        
        # Security
        if os.getenv('SECRET_KEY'):
            config.secret_key = os.getenv('SECRET_KEY')
        
        if os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'):
            config.access_token_expire_minutes = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES'))
        
        # Feature flags
        config.enable_ocr = os.getenv('ENABLE_OCR', 'true').lower() == 'true'
        config.enable_magic_detection = os.getenv('ENABLE_MAGIC_DETECTION', 'true').lower() == 'true'
        config.debug_mode = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
        
        # Logging
        config.log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        config.log_to_file = os.getenv('LOG_TO_FILE', 'false').lower() == 'true'
        if os.getenv('LOG_FILE_PATH'):
            config.log_file_path = os.getenv('LOG_FILE_PATH')
        
        return config
    
    @classmethod
    def from_file(cls, config_file: str) -> 'SystemConfig':
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            config = cls()
            
            # Update file size limits
            if 'file_size_limits' in data:
                for key, value in data['file_size_limits'].items():
                    if hasattr(config.file_size_limits, key):
                        # Convert MB to bytes if the key ends with _mb
                        if key.endswith('_mb'):
                            value = value * 1024 * 1024
                            key = key[:-3]  # Remove _mb suffix
                        setattr(config.file_size_limits, key, value)
            
            # Update processing limits
            if 'processing_limits' in data:
                for key, value in data['processing_limits'].items():
                    if hasattr(config.processing_limits, key):
                        setattr(config.processing_limits, key, value)
            
            # Update other settings
            for key, value in data.items():
                if hasattr(config, key) and key not in ['file_size_limits', 'processing_limits']:
                    setattr(config, key, value)
            
            logger.info(f"Configuration loaded from {config_file}")
            return config
            
        except FileNotFoundError:
            logger.warning(f"Configuration file {config_file} not found, using defaults")
            return cls.from_env()
        except Exception as e:
            logger.error(f"Error loading configuration from {config_file}: {e}")
            return cls.from_env()
    
    def save_to_file(self, config_file: str):
        """Save current configuration to JSON file"""
        try:
            # Convert to dictionary for JSON serialization
            config_dict = {
                'file_size_limits': {
                    'default_upload_limit_mb': self.file_size_limits.to_mb(self.file_size_limits.default_upload_limit),
                    'pdf_max_size_mb': self.file_size_limits.to_mb(self.file_size_limits.pdf_max_size),
                    'image_max_size_mb': self.file_size_limits.to_mb(self.file_size_limits.image_max_size),
                    'text_max_size_mb': self.file_size_limits.to_mb(self.file_size_limits.text_max_size),
                    'docx_max_size_mb': self.file_size_limits.to_mb(self.file_size_limits.docx_max_size),
                },
                'processing_limits': {
                    'max_pdf_pages': self.processing_limits.max_pdf_pages,
                    'max_text_length': self.processing_limits.max_text_length,
                    'processing_timeout_seconds': self.processing_limits.processing_timeout_seconds,
                },
                'database_url': self.database_url,
                'access_token_expire_minutes': self.access_token_expire_minutes,
                'enable_ocr': self.enable_ocr,
                'enable_magic_detection': self.enable_magic_detection,
                'debug_mode': self.debug_mode,
                'log_level': self.log_level,
                'log_to_file': self.log_to_file,
                'log_file_path': self.log_file_path
            }
            
            with open(config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            
            logger.info(f"Configuration saved to {config_file}")
            
        except Exception as e:
            logger.error(f"Error saving configuration to {config_file}: {e}")
    
    def get_user_limits_info(self, user_tier: str = 'basic') -> Dict[str, Any]:
        """Get user limits information for API responses"""
        return {
            'file_size_limits': {
                'pdf_max_mb': self.file_size_limits.to_mb(
                    self.file_size_limits.get_limit_for_user(user_tier, 'pdf')
                ),
                'image_max_mb': self.file_size_limits.to_mb(
                    self.file_size_limits.get_limit_for_user(user_tier, 'image')
                ),
                'text_max_mb': self.file_size_limits.to_mb(
                    self.file_size_limits.get_limit_for_user(user_tier, 'text')
                ),
                'docx_max_mb': self.file_size_limits.to_mb(
                    self.file_size_limits.get_limit_for_user(user_tier, 'docx')
                ),
                'default_max_mb': self.file_size_limits.to_mb(
                    self.file_size_limits.get_limit_for_user(user_tier, 'default')
                ),
            },
            'processing_limits': {
                'max_pdf_pages': self.processing_limits.get_limit_for_user(user_tier, 'pdf_pages'),
                'max_text_length': self.processing_limits.get_limit_for_user(user_tier, 'text_length'),
                'max_concurrent_jobs': self.processing_limits.get_limit_for_user(user_tier, 'concurrent_jobs'),
                'timeout_seconds': self.processing_limits.get_limit_for_user(user_tier, 'timeout'),
            },
            'user_tier': user_tier
        }

# Global configuration instance
_config: Optional[SystemConfig] = None

def get_config() -> SystemConfig:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        # Try to load from config file first, then environment
        config_file = os.getenv('CONFIG_FILE', './config.json')
        _config = SystemConfig.from_file(config_file)
    return _config

def reload_config():
    """Reload configuration from file/environment"""
    global _config
    _config = None
    return get_config()

def update_config(**kwargs):
    """Update configuration values"""
    config = get_config()
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
        elif hasattr(config.file_size_limits, key):
            setattr(config.file_size_limits, key, value)
        elif hasattr(config.processing_limits, key):
            setattr(config.processing_limits, key, value)
    
    # Save updated configuration
    config_file = os.getenv('CONFIG_FILE', './config.json')
    config.save_to_file(config_file)
    
    logger.info(f"Configuration updated with: {kwargs}")