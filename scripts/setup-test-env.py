#!/usr/bin/env python3
"""
Test environment setup script for AI De-identification System
"""
import os
import sys
import subprocess
import asyncio
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from src.core.config import settings
from src.core.database import DatabaseManager


def run_command(command, description):
    """Run a shell command and check for errors"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} - Success")
        if result.stdout.strip():
            print(f"   Output: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - Failed")
        print(f"   Error: {e.stderr.strip() if e.stderr else 'Unknown error'}")
        return False


def check_dependencies():
    """Check if all required dependencies are available"""
    print("🔍 Checking dependencies...")
    
    dependencies = [
        ("python", "python --version"),
        ("docker", "docker --version"),
        ("docker-compose", "docker-compose --version"),
    ]
    
    all_good = True
    for name, command in dependencies:
        if run_command(command, f"Checking {name}"):
            continue
        else:
            all_good = False
    
    return all_good


def setup_directories():
    """Create necessary directories"""
    print("📁 Setting up directories...")
    
    directories = [
        settings.UPLOAD_PATH,
        settings.OUTPUT_PATH,
        settings.TEMP_PATH,
        settings.PRESIDIO_MODELS_PATH,
        Path(settings.LOG_FILE).parent,
        "test_data"
    ]
    
    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {path}")


def create_env_file():
    """Create .env file from .env.example"""
    print("⚙️ Setting up environment configuration...")
    
    env_example = project_root / ".env.example"
    env_file = project_root / ".env"
    
    if env_file.exists():
        print("✅ .env file already exists")
        return
    
    if env_example.exists():
        import shutil
        shutil.copy(env_example, env_file)
        print("✅ Created .env file from .env.example")
    else:
        print("❌ .env.example not found")


def create_test_documents():
    """Create sample test documents with PII"""
    print("📄 Creating test documents...")
    
    test_data_dir = Path("test_data")
    test_data_dir.mkdir(exist_ok=True)
    
    # Test document 1: Medical report with HIPAA-sensitive data
    medical_doc = """
MEDICAL CONSULTATION REPORT

Patient Information:
Name: John Michael Smith
Date of Birth: March 15, 1985
Social Security Number: 123-45-6789
Phone Number: (555) 123-4567
Email: john.smith@email.com
Address: 123 Main Street, Anytown, NY 12345

Medical Record Number: MRN-789456
Date of Visit: December 8, 2024

CONSULTATION SUMMARY:
Patient John Smith visited our clinic today for routine checkup. 
His phone number (555) 123-4567 is on file for follow-up appointments.
Insurance card shows member ID: INS-987654321.

The patient's primary care physician Dr. Sarah Johnson can be reached at sarah.johnson@clinic.com.
Patient requested that bills be sent to his home address at 123 Main Street, Anytown, NY 12345.

DIAGNOSIS:
Patient is in good health with no significant findings.

FOLLOW-UP:
Schedule appointment in 6 months. Contact patient at john.smith@email.com with reminder.

Physician: Dr. Emily Rodriguez, MD
License Number: MD-456789
Date: December 8, 2024
    """
    
    # Test document 2: Financial document with PCI-DSS sensitive data
    financial_doc = """
BANK STATEMENT - CONFIDENTIAL

Customer: Jane Elizabeth Doe
Account Number: 1234567890123456
Social Security Number: 987-65-4321
Date of Birth: July 22, 1990
Phone: +1 (555) 987-6543
Email: jane.doe@example.org

Address: 456 Oak Avenue, Suite 200, Springfield, CA 90210

TRANSACTION HISTORY - November 2024

Date        Description                     Amount
11/01/2024  Direct Deposit - ACME Corp     +$3,250.00
11/05/2024  ATM Withdrawal                  -$200.00
11/10/2024  Credit Card Payment             -$1,450.25
    Card: **** **** **** 8901
11/15/2024  Online Transfer to Savings      -$500.00
11/20/2024  Check #1234 - Rent Payment      -$1,800.00
11/25/2024  Auto Loan Payment               -$425.75
    Account: AUTO-LOAN-789456123

Customer Service: For questions, call us at 1-800-555-0199 or 
email support@bank.com. You can also visit our website at www.bank.com.

Important: Please keep this statement secure. Contains sensitive financial information.
If you notice any unauthorized transactions, contact us immediately at (555) 123-BANK.

Statement Period: November 1-30, 2024
Customer ID: CUST-2024-789456
Routing Number: 123456789
    """
    
    # Test document 3: HR document with employment data
    hr_doc = """
EMPLOYEE CONFIDENTIAL INFORMATION

PERSONAL DETAILS:
Full Name: Michael Anthony Williams  
Employee ID: EMP-2024-001
Social Security Number: 456-78-9012
Date of Birth: September 10, 1988
Phone Number: (555) 456-7890
Personal Email: m.williams@personalmail.com
Work Email: michael.williams@company.com

HOME ADDRESS:
789 Pine Street, Apt 4B
Riverside, FL 33101

EMERGENCY CONTACT:
Name: Sarah Williams (Spouse)
Relationship: Wife
Phone: (555) 456-7891
Email: sarah.w@email.com

EMPLOYMENT INFORMATION:
Position: Software Engineer
Department: Technology
Manager: David Chen (david.chen@company.com)
Start Date: January 15, 2024
Salary: $95,000.00 annually

BANKING INFORMATION:
Bank: First National Bank
Routing Number: 987654321
Account Number: 1122334455
Account Type: Checking

BENEFITS ENROLLMENT:
Health Insurance: Enrolled - Policy #HI-789456123
Dental Insurance: Enrolled - Policy #DI-456789012
401(k): Contributing 6% - Account #401K-789123456

IP Address (VPN Access): 192.168.1.105
Last Login: December 8, 2024 at 2:30 PM EST

This document contains confidential and proprietary information.
Unauthorized disclosure is prohibited.
    """
    
    # Save test documents
    test_docs = [
        ("medical_report.txt", medical_doc),
        ("financial_statement.txt", financial_doc),
        ("employee_record.txt", hr_doc)
    ]
    
    for filename, content in test_docs:
        file_path = test_data_dir / filename
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content.strip())
        print(f"✅ Created test document: {filename}")
    
    print(f"📄 Created {len(test_docs)} test documents in {test_data_dir}")


async def test_database_connection():
    """Test database connection"""
    print("🗄️ Testing database connection...")
    
    try:
        # Try sync connection first
        if DatabaseManager.health_check_sync():
            print("✅ Database connection successful (sync)")
        else:
            print("❌ Database connection failed (sync)")
            return False
        
        # Try async connection
        if await DatabaseManager.health_check():
            print("✅ Database connection successful (async)")
            return True
        else:
            print("❌ Database connection failed (async)")
            return False
            
    except Exception as e:
        print(f"❌ Database connection test failed: {e}")
        return False


def install_python_dependencies():
    """Install Python dependencies"""
    print("📦 Installing Python dependencies...")
    
    commands = [
        "pip install --upgrade pip",
        "pip install -r requirements.txt",
        "python -m spacy download en_core_web_sm"
    ]
    
    success = True
    for command in commands:
        if not run_command(command, f"Running: {command}"):
            success = False
    
    return success


def main():
    """Main setup function"""
    print("🚀 Setting up AI De-identification System Test Environment")
    print("=" * 60)
    
    steps = [
        ("Check dependencies", check_dependencies),
        ("Setup directories", setup_directories),
        ("Create environment file", create_env_file),
        ("Install Python dependencies", install_python_dependencies),
        ("Create test documents", create_test_documents),
    ]
    
    for step_name, step_func in steps:
        print(f"\n📋 Step: {step_name}")
        try:
            if asyncio.iscoroutinefunction(step_func):
                result = asyncio.run(step_func())
            else:
                result = step_func()
            
            if result is False:
                print(f"❌ Step failed: {step_name}")
                print("⚠️  Setup incomplete. Please resolve the issues above.")
                return False
                
        except Exception as e:
            print(f"❌ Step failed with exception: {step_name}")
            print(f"   Error: {e}")
            return False
    
    print("\n" + "=" * 60)
    print("✅ Test environment setup completed successfully!")
    print("\n🔧 Next steps:")
    print("1. Start Docker services: docker-compose up -d")
    print("2. Run the application: python src/api/main.py")
    print("3. Open browser to: http://localhost:8000")
    print("4. Test with documents in test_data/ directory")
    print("\n📝 Test documents created:")
    print("- medical_report.txt (HIPAA-sensitive)")
    print("- financial_statement.txt (PCI-DSS sensitive)")  
    print("- employee_record.txt (HR/Employment data)")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)