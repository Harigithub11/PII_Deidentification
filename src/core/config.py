"""
Application configuration management
"""
import os
from pathlib import Path
from typing import List, Optional

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = Field(default="AI De-identification System", env="APP_NAME")
    APP_VERSION: str = Field(default="1.0.0", env="APP_VERSION")
    API_V1_STR: str = Field(default="/api/v1", env="API_V1_STR")
    SECRET_KEY: str = Field(default="dev-secret-key-change-in-production", env="SECRET_KEY")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    DEBUG: bool = Field(default=False, env="DEBUG")
    
    # Database
    DATABASE_URL: str = Field(
        default="postgresql://deidentify_user:secure_password@localhost:5432/deidentify_db",
        env="DATABASE_URL"
    )
    DATABASE_ECHO: bool = Field(default=False, env="DATABASE_ECHO")
    
    # File Storage
    UPLOAD_PATH: str = Field(default="./data/input", env="UPLOAD_PATH")
    OUTPUT_PATH: str = Field(default="./data/output", env="OUTPUT_PATH")
    TEMP_PATH: str = Field(default="./data/temp", env="TEMP_PATH")
    MAX_FILE_SIZE: int = Field(default=100_000_000, env="MAX_FILE_SIZE")  # 100MB
    ALLOWED_FILE_TYPES: List[str] = [
        "application/pdf",
        "image/jpeg", 
        "image/jpg", 
        "image/png", 
        "image/tiff",
        "text/plain"
    ]
    
    # OCR Configuration
    TESSERACT_CMD: str = Field(default="tesseract", env="TESSERACT_CMD")
    OCR_LANGUAGES: str = Field(default="eng", env="OCR_LANGUAGES")
    OCR_CONFIDENCE_THRESHOLD: int = Field(default=60, env="OCR_CONFIDENCE_THRESHOLD")
    
    # PII Detection Configuration
    PRESIDIO_MODELS_PATH: str = Field(default="./models", env="PRESIDIO_MODELS_PATH")
    SPACY_MODEL: str = Field(default="en_core_web_sm", env="SPACY_MODEL")
    PII_CONFIDENCE_THRESHOLD: float = Field(default=0.8, env="PII_CONFIDENCE_THRESHOLD")
    
    # Workflow Configuration
    PREFECT_SERVER_URL: str = Field(default="http://localhost:4200", env="PREFECT_SERVER_URL")
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    
    # Logging
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    LOG_FILE: str = Field(default="./logs/app.log", env="LOG_FILE")
    
    # Security
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000", 
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000"
    ]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Performance
    MAX_WORKERS: int = Field(default=4, env="MAX_WORKERS")
    BATCH_SIZE: int = Field(default=10, env="BATCH_SIZE")
    PROCESSING_TIMEOUT: int = Field(default=300, env="PROCESSING_TIMEOUT")  # 5 minutes
    
    # Paths validation and creation
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._create_directories()
    
    def _create_directories(self):
        """Create necessary directories if they don't exist"""
        directories = [
            self.UPLOAD_PATH,
            self.OUTPUT_PATH,
            self.TEMP_PATH,
            self.PRESIDIO_MODELS_PATH,
            Path(self.LOG_FILE).parent
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    @property
    def database_url_async(self) -> str:
        """Get async database URL for SQLAlchemy"""
        return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://")
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Create global settings instance
settings = Settings()