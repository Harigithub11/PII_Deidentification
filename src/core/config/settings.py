"""
Main configuration settings for PII De-identification System

This module provides centralized configuration management using Pydantic settings.
"""

import os
from pathlib import Path
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Main application settings."""
    
    # Application Settings
    app_name: str = Field(default="PII De-identification System", env="APP_NAME")
    app_version: str = Field(default="1.0.0", env="APP_VERSION")
    debug: bool = Field(default=True, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    
    # API Configuration
    api_host: str = Field(default="localhost", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=1, env="API_WORKERS")
    api_reload: bool = Field(default=True, env="API_RELOAD")
    
    # Frontend Configuration
    frontend_url: str = Field(default="http://localhost:3000", env="FRONTEND_URL")
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        env="CORS_ORIGINS"
    )
    
    # Database Configuration
    database_url: str = Field(
        default="sqlite:///./data/pii_system.db",
        env="DATABASE_URL"
    )
    database_pool_size: int = Field(default=5, env="DATABASE_POOL_SIZE")
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")
    
    # Model Configuration
    model_cache_dir: str = Field(default="./models/cache", env="MODEL_CACHE_DIR")
    model_download_dir: str = Field(default="./models/downloads", env="MODEL_DOWNLOAD_DIR")
    enable_gpu: bool = Field(default=True, env="ENABLE_GPU")
    max_gpu_memory_mb: int = Field(default=6000, env="MAX_GPU_MEMORY_MB")
    model_device: str = Field(default="cuda", env="MODEL_DEVICE")
    
    # Mistral Configuration
    mistral_model: str = Field(default="mistral:7b-instruct", env="MISTRAL_MODEL")
    mistral_timeout: int = Field(default=300, env="MISTRAL_TIMEOUT")
    mistral_max_tokens: int = Field(default=512, env="MISTRAL_MAX_TOKENS")
    mistral_temperature: float = Field(default=0.1, env="MISTRAL_TEMPERATURE")
    
    # Security
    secret_key: str = Field(
        default="your-secret-key-here-change-in-production",
        env="SECRET_KEY"
    )
    encryption_key: str = Field(
        default="your-encryption-key-here-change-in-production",
        env="ENCRYPTION_KEY"
    )
    max_file_size_mb: int = Field(default=50, env="MAX_FILE_SIZE_MB")
    allowed_file_types: List[str] = Field(
        default=["pdf", "png", "jpg", "jpeg", "tiff", "tif"],
        env="ALLOWED_FILE_TYPES"
    )
    
    # Authentication & Authorization
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    password_reset_expire_hours: int = Field(default=1, env="PASSWORD_RESET_EXPIRE_HOURS")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    initial_admin_email: Optional[str] = Field(default=None, env="INITIAL_ADMIN_EMAIL")
    
    # Rate Limiting
    rate_limit_requests_per_minute: int = Field(default=60, env="RATE_LIMIT_REQUESTS_PER_MINUTE")
    rate_limit_burst_requests: int = Field(default=10, env="RATE_LIMIT_BURST_REQUESTS")
    upload_rate_limit_per_minute: int = Field(default=5, env="UPLOAD_RATE_LIMIT_PER_MINUTE")
    
    # Security Headers
    enable_security_headers: bool = Field(default=True, env="ENABLE_SECURITY_HEADERS")
    enable_hsts: bool = Field(default=True, env="ENABLE_HSTS")
    hsts_max_age: int = Field(default=31536000, env="HSTS_MAX_AGE")  # 1 year
    
    # IP Whitelist for Admin
    admin_ip_whitelist: List[str] = Field(
        default=["127.0.0.1", "::1"],
        env="ADMIN_IP_WHITELIST"
    )
    
    # Session Security
    secure_cookies: bool = Field(default=True, env="SECURE_COOKIES")
    session_timeout_minutes: int = Field(default=60, env="SESSION_TIMEOUT_MINUTES")
    
    # Audit & Compliance
    enable_audit_logging: bool = Field(default=True, env="ENABLE_AUDIT_LOGGING")
    audit_log_retention_days: int = Field(default=90, env="AUDIT_LOG_RETENTION_DAYS")
    enable_request_logging: bool = Field(default=True, env="ENABLE_REQUEST_LOGGING")
    
    # Data Protection
    enable_pii_encryption: bool = Field(default=True, env="ENABLE_PII_ENCRYPTION")
    enable_data_masking: bool = Field(default=True, env="ENABLE_DATA_MASKING")
    data_retention_days: int = Field(default=30, env="DATA_RETENTION_DAYS")
    
    # Processing Configuration
    max_concurrent_jobs: int = Field(default=2, env="MAX_CONCURRENT_JOBS")
    job_timeout_minutes: int = Field(default=30, env="JOB_TIMEOUT_MINUTES")
    cleanup_temp_files_hours: int = Field(default=24, env="CLEANUP_TEMP_FILES_HOURS")
    batch_size: int = Field(default=10, env="BATCH_SIZE")
    
    # Airflow Configuration
    airflow_home: str = Field(default="./orchestration", env="AIRFLOW_HOME")
    airflow_webserver_port: int = Field(default=8080, env="AIRFLOW_WEBSERVER_PORT")
    airflow_executor: str = Field(default="LocalExecutor", env="AIRFLOW_EXECUTOR")
    airflow_database_url: str = Field(
        default="sqlite:///./data/airflow.db",
        env="AIRFLOW_DATABASE_URL"
    )
    
    # OCR Configuration
    tesseract_languages: List[str] = Field(
        default=["eng", "hin"],
        env="TESSERACT_LANGUAGES"
    )
    paddleocr_use_gpu: bool = Field(default=True, env="PADDLEOCR_USE_GPU")
    ocr_confidence_threshold: float = Field(default=0.7, env="OCR_CONFIDENCE_THRESHOLD")
    
    # PII Detection Configuration
    spacy_model: str = Field(default="en_core_web_lg", env="SPACY_MODEL")
    pii_confidence_threshold: float = Field(default=0.8, env="PII_CONFIDENCE_THRESHOLD")
    enable_custom_ner: bool = Field(default=True, env="ENABLE_CUSTOM_NER")
    
    # Storage Configuration
    upload_dir: str = Field(default="./data/input", env="UPLOAD_DIR")
    processing_dir: str = Field(default="./data/processing", env="PROCESSING_DIR")
    output_dir: str = Field(default="./data/output", env="OUTPUT_DIR")
    audit_dir: str = Field(default="./data/audit", env="AUDIT_DIR")
    temp_dir: str = Field(default="./data/temp", env="TEMP_DIR")
    
    # Logging Configuration
    log_file: str = Field(default="./logs/application.log", env="LOG_FILE")
    log_max_size_mb: int = Field(default=100, env="LOG_MAX_SIZE_MB")
    log_backup_count: int = Field(default=5, env="LOG_BACKUP_COUNT")
    
    # Monitoring Configuration
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")
    health_check_interval: int = Field(default=30, env="HEALTH_CHECK_INTERVAL")
    
    # Development Configuration
    enable_debug_endpoints: bool = Field(default=True, env="ENABLE_DEBUG_ENDPOINTS")
    enable_swagger_ui: bool = Field(default=True, env="ENABLE_SWAGGER_UI")
    enable_reload: bool = Field(default=True, env="ENABLE_RELOAD")
    
    @field_validator('model_device')
    @classmethod
    def validate_model_device(cls, v):
        """Validate model device setting."""
        if v not in ['cpu', 'cuda', 'mps']:
            raise ValueError('model_device must be one of: cpu, cuda, mps')
        return v
    
    @field_validator('max_gpu_memory_mb')
    @classmethod
    def validate_gpu_memory(cls, v):
        """Validate GPU memory setting."""
        if v <= 0:
            raise ValueError('max_gpu_memory_mb must be positive')
        if v > 32000:  # 32GB max reasonable limit
            raise ValueError('max_gpu_memory_mb cannot exceed 32000')
        return v
    
    @field_validator('allowed_file_types')
    @classmethod
    def validate_file_types(cls, v):
        """Validate allowed file types."""
        valid_types = ['pdf', 'png', 'jpg', 'jpeg', 'tiff', 'tif', 'bmp', 'gif']
        for file_type in v:
            if file_type.lower() not in valid_types:
                raise ValueError(f'Invalid file type: {file_type}')
        return [ft.lower() for ft in v]
    
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False
    }
        
    def get_model_cache_path(self) -> Path:
        """Get the model cache directory path."""
        return Path(self.model_cache_dir).resolve()
    
    def get_model_download_path(self) -> Path:
        """Get the model download directory path."""
        return Path(self.model_download_dir).resolve()
    
    def get_data_paths(self) -> dict:
        """Get all data directory paths."""
        return {
            'upload': Path(self.upload_dir).resolve(),
            'processing': Path(self.processing_dir).resolve(),
            'output': Path(self.output_dir).resolve(),
            'audit': Path(self.audit_dir).resolve(),
            'temp': Path(self.temp_dir).resolve(),
        }
    
    def is_gpu_available(self) -> bool:
        """Check if GPU is available and enabled."""
        if not self.enable_gpu:
            return False
        
        try:
            import torch
            return torch.cuda.is_available()
        except ImportError:
            return False


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings
