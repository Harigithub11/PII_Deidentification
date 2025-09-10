#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Start Script for PII De-identification System

This script provides a simple way to get the system up and running quickly.
"""

import os
import sys
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any

# Configure UTF-8 environment for Windows compatibility
if sys.platform == 'win32':
    os.environ['PYTHONUTF8'] = '1'
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    try:
        os.system('chcp 65001 >nul 2>&1')
    except:
        pass

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class QuickStart:
    """Handles quick start setup for the PII De-identification System."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.venv_path = self.project_root / "venv"
        self.requirements_file = self.project_root / "requirements.txt"
        
    def run_quick_start(self):
        """Run the complete quick start process."""
        print("[START] PII De-identification System - Quick Start")
        print("=" * 60)
        
        try:
            # Check Python version
            self._check_python_version()
            
            # Create virtual environment
            self._create_virtual_environment()
            
            # Install dependencies
            self._install_dependencies()
            
            # Setup models
            self._setup_models()
            
            # Initialize database
            self._initialize_database()
            
            # Setup Airflow
            self._setup_airflow()
            
            # Health check
            self._run_health_check()
            
            print("\n[SUCCESS] Quick start completed successfully!")
            print("\nNext steps:")
            print("1. Activate virtual environment:")
            print(f"   Windows: {self.venv_path}\\Scripts\\activate")
            print(f"   Linux/Mac: source {self.venv_path}/bin/activate")
            print("2. Start the system:")
            print("   python scripts/deployment/start_services.py")
            print("3. Access the web interface: http://localhost:8000")
            
        except Exception as e:
            print(f"\n[ERROR] Quick start failed: {e}")
            print("Please check the error messages above and try again.")
            sys.exit(1)
    
    def _check_python_version(self):
        """Check if Python version is compatible."""
        print("[CHECK] Checking Python version...")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 9):
            raise Exception(f"Python 3.9+ required, found {version.major}.{version.minor}")
        
        print(f"[OK] Python {version.major}.{version.minor}.{version.micro} - Compatible")
    
    def _create_virtual_environment(self):
        """Create Python virtual environment."""
        print("\n[VENV] Creating virtual environment...")
        
        if self.venv_path.exists():
            print("[OK] Virtual environment already exists")
            return
        
        try:
            subprocess.run(
                [sys.executable, "-m", "venv", str(self.venv_path)],
                check=True,
                capture_output=True
            )
            print("[OK] Virtual environment created successfully")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to create virtual environment: {e}")
    
    def _get_pip_command(self) -> List[str]:
        """Get the pip command for the virtual environment."""
        if os.name == 'nt':  # Windows
            pip_path = self.venv_path / "Scripts" / "pip.exe"
        else:  # Linux/Mac
            pip_path = self.venv_path / "bin" / "pip"
        
        return [str(pip_path)]
    
    def _install_dependencies(self):
        """Install Python dependencies."""
        print("\n[INSTALL] Installing dependencies...")
        
        pip_cmd = self._get_pip_command()
        
        try:
            # Upgrade pip
            subprocess.run(
                pip_cmd + ["install", "--upgrade", "pip"],
                check=True,
                capture_output=True
            )
            print("[OK] pip upgraded")
            
            # Install requirements
            subprocess.run(
                pip_cmd + ["install", "-r", str(self.requirements_file)],
                check=True,
                capture_output=True
            )
            print("[OK] Dependencies installed successfully")
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to install dependencies: {e}")
    
    def _setup_models(self):
        """Setup AI models."""
        print("\n[AI] Setting up AI models...")
        
        try:
            # Run model installation script
            script_path = self.project_root / "scripts" / "setup" / "install_models.py"
            
            # Use the virtual environment's Python
            if os.name == 'nt':  # Windows
                python_path = self.venv_path / "Scripts" / "python.exe"
            else:  # Linux/Mac
                python_path = self.venv_path / "bin" / "python"
            
            subprocess.run(
                [str(python_path), str(script_path)],
                check=True,
                cwd=self.project_root
            )
            print("[OK] AI models setup completed")
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to setup AI models: {e}")
    
    def _initialize_database(self):
        """Initialize the database."""
        print("\n[DATABASE] Initializing database...")
        
        try:
            # Create database directory
            db_dir = self.project_root / "data"
            db_dir.mkdir(exist_ok=True)
            
            # Create SQLite database file
            db_file = db_dir / "pii_system.db"
            if not db_file.exists():
                db_file.touch()
                print("[OK] Database file created")
            else:
                print("[OK] Database file already exists")
                
        except Exception as e:
            raise Exception(f"Failed to initialize database: {e}")
    
    def _setup_airflow(self):
        """Setup Apache Airflow."""
        print("\n[AIRFLOW] Setting up Apache Airflow...")
        
        try:
            # Set Airflow environment variables
            os.environ['AIRFLOW_HOME'] = str(self.project_root / "orchestration")
            
            # Create Airflow directories
            airflow_dirs = [
                "orchestration/dags",
                "orchestration/logs",
                "logs/airflow"
            ]
            
            for dir_path in airflow_dirs:
                full_path = self.project_root / dir_path
                full_path.mkdir(parents=True, exist_ok=True)
            
            print("[OK] Airflow directories created")
            
            # Note: Airflow will be fully configured when the system starts
            print("[INFO] Airflow will be configured on first startup")
            
        except Exception as e:
            raise Exception(f"Failed to setup Airflow: {e}")
    
    def _run_health_check(self):
        """Run a basic health check."""
        print("\n[HEALTH] Running health check...")
        
        try:
            # Check if key directories exist
            required_dirs = [
                "src",
                "config", 
                "data",
                "models",
                "logs",
                "tests"
            ]
            
            for dir_name in required_dirs:
                dir_path = self.project_root / dir_name
                if not dir_path.exists():
                    raise Exception(f"Required directory missing: {dir_name}")
            
            # Check if key files exist
            required_files = [
                "requirements.txt",
                "README.md",
                "src/core/config/settings.py",
                "src/core/models/model_manager.py"
            ]
            
            for file_name in required_files:
                file_path = self.project_root / file_name
                if not file_path.exists():
                    raise Exception(f"Required file missing: {file_name}")
            
            print("[OK] Health check passed")
            
        except Exception as e:
            raise Exception(f"Health check failed: {e}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        return {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "platform": sys.platform,
            "project_root": str(self.project_root),
            "virtual_environment": str(self.venv_path),
            "requirements_file": str(self.requirements_file)
        }


def main():
    """Main function for quick start."""
    quick_start = QuickStart()
    
    # Print system info
    system_info = quick_start.get_system_info()
    print("System Information:")
    print(f"  Python: {system_info['python_version']}")
    print(f"  Platform: {system_info['platform']}")
    print(f"  Project Root: {system_info['project_root']}")
    print()
    
    # Run quick start
    quick_start.run_quick_start()


if __name__ == "__main__":
    main()
