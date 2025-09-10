#!/usr/bin/env python3
"""
Comprehensive Test Runner for PII De-identification System

This script runs the complete test suite with different configurations
and generates comprehensive reports.
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Any
import json
import time
from datetime import datetime


class TestRunner:
    """Comprehensive test runner with reporting."""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.test_dir = self.project_root / "tests"
        self.results = {}
    
    def setup_environment(self):
        """Set up test environment variables."""
        env_vars = {
            "TEST_MODE": "true",
            "DATABASE_URL": "sqlite:///test.db",
            "REDIS_URL": "redis://localhost:6379/15",
            "SECRET_KEY": "test-secret-key-for-testing-only",
            "ENCRYPTION_KEY": "test-encryption-key-32-bytes-long",
            "LOG_LEVEL": "ERROR"  # Reduce log noise during tests
        }
        
        for key, value in env_vars.items():
            os.environ[key] = value
    
    def run_unit_tests(self) -> Dict[str, Any]:
        """Run unit tests."""
        print("🧪 Running Unit Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/unit/",
            "-v", "--tb=short",
            "--cov=src",
            "--cov-report=html:htmlcov/unit",
            "--cov-report=xml:coverage_unit.xml",
            "--cov-report=term-missing",
            "--junit-xml=test-results/unit-results.xml",
            "-m", "unit"
        ]
        
        result = self._run_command(cmd, "Unit Tests")
        return result
    
    def run_integration_tests(self) -> Dict[str, Any]:
        """Run integration tests."""
        print("🔗 Running Integration Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/integration/",
            "-v", "--tb=short",
            "--junit-xml=test-results/integration-results.xml",
            "-m", "integration"
        ]
        
        result = self._run_command(cmd, "Integration Tests")
        return result
    
    def run_api_tests(self) -> Dict[str, Any]:
        """Run API tests."""
        print("🌐 Running API Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/",
            "-v", "--tb=short",
            "--junit-xml=test-results/api-results.xml",
            "-m", "api"
        ]
        
        result = self._run_command(cmd, "API Tests")
        return result
    
    def run_security_tests(self) -> Dict[str, Any]:
        """Run security tests."""
        print("🔒 Running Security Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/security/",
            "-v", "--tb=short",
            "--junit-xml=test-results/security-results.xml",
            "-m", "security"
        ]
        
        result = self._run_command(cmd, "Security Tests")
        return result
    
    def run_performance_tests(self) -> Dict[str, Any]:
        """Run performance tests."""
        print("⚡ Running Performance Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/performance/",
            "-v", "--tb=short",
            "--junit-xml=test-results/performance-results.xml",
            "-m", "performance and not slow"
        ]
        
        result = self._run_command(cmd, "Performance Tests")
        return result
    
    def run_compliance_tests(self) -> Dict[str, Any]:
        """Run compliance tests."""
        print("📋 Running Compliance Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/compliance/",
            "-v", "--tb=short",
            "--junit-xml=test-results/compliance-results.xml",
            "-m", "compliance"
        ]
        
        result = self._run_command(cmd, "Compliance Tests")
        return result
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all tests with comprehensive coverage."""
        print("🎯 Running Complete Test Suite...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/",
            "-v", "--tb=short",
            "--cov=src",
            "--cov-report=html:htmlcov",
            "--cov-report=xml:coverage.xml",
            "--cov-report=term-missing",
            "--cov-fail-under=85",
            "--junit-xml=test-results/all-results.xml",
            "--maxfail=10",
            "--durations=10"
        ]
        
        result = self._run_command(cmd, "All Tests")
        return result
    
    def run_smoke_tests(self) -> Dict[str, Any]:
        """Run smoke tests for quick validation."""
        print("💨 Running Smoke Tests...")
        
        cmd = [
            "python", "-m", "pytest",
            "tests/",
            "-v", "--tb=short",
            "--junit-xml=test-results/smoke-results.xml",
            "-m", "smoke or (unit and not slow)",
            "--maxfail=5"
        ]
        
        result = self._run_command(cmd, "Smoke Tests")
        return result
    
    def _run_command(self, cmd: List[str], test_type: str) -> Dict[str, Any]:
        """Run a command and capture results."""
        start_time = time.time()
        
        try:
            # Ensure results directory exists
            os.makedirs("test-results", exist_ok=True)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=600  # 10 minutes timeout
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            return {
                "test_type": test_type,
                "return_code": result.returncode,
                "duration": duration,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0,
                "timestamp": datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                "test_type": test_type,
                "return_code": -1,
                "duration": 600,
                "error": "Test execution timed out",
                "success": False,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "test_type": test_type,
                "return_code": -1,
                "duration": time.time() - start_time,
                "error": str(e),
                "success": False,
                "timestamp": datetime.now().isoformat()
            }
    
    def run_linting_checks(self) -> Dict[str, Any]:
        """Run code linting and style checks."""
        print("📝 Running Code Quality Checks...")
        
        checks = {}
        
        # Black formatting check
        print("  → Checking code formatting (Black)...")
        black_result = subprocess.run(
            ["python", "-m", "black", "--check", "--diff", "src/", "tests/"],
            capture_output=True,
            text=True
        )
        checks["black"] = {
            "success": black_result.returncode == 0,
            "output": black_result.stdout + black_result.stderr
        }
        
        # Flake8 linting
        print("  → Running linter (Flake8)...")
        flake8_result = subprocess.run(
            ["python", "-m", "flake8", "src/", "tests/", "--max-line-length=88"],
            capture_output=True,
            text=True
        )
        checks["flake8"] = {
            "success": flake8_result.returncode == 0,
            "output": flake8_result.stdout + flake8_result.stderr
        }
        
        # MyPy type checking
        print("  → Type checking (MyPy)...")
        mypy_result = subprocess.run(
            ["python", "-m", "mypy", "src/", "--ignore-missing-imports"],
            capture_output=True,
            text=True
        )
        checks["mypy"] = {
            "success": mypy_result.returncode == 0,
            "output": mypy_result.stdout + mypy_result.stderr
        }
        
        return checks
    
    def run_security_scans(self) -> Dict[str, Any]:
        """Run security scanning tools."""
        print("🔍 Running Security Scans...")
        
        scans = {}
        
        # Bandit security scan
        print("  → Security scan (Bandit)...")
        bandit_result = subprocess.run(
            ["python", "-m", "bandit", "-r", "src/", "-f", "json"],
            capture_output=True,
            text=True
        )
        scans["bandit"] = {
            "success": bandit_result.returncode == 0,
            "output": bandit_result.stdout,
            "issues_found": bandit_result.returncode != 0
        }
        
        # Safety dependency check
        print("  → Dependency vulnerability scan (Safety)...")
        safety_result = subprocess.run(
            ["python", "-m", "safety", "check", "--json"],
            capture_output=True,
            text=True
        )
        scans["safety"] = {
            "success": safety_result.returncode == 0,
            "output": safety_result.stdout,
            "vulnerabilities_found": safety_result.returncode != 0
        }
        
        return scans
    
    def generate_summary_report(self) -> str:
        """Generate summary report of all test results."""
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        total_duration = 0
        
        report_lines = [
            "=" * 80,
            "📊 COMPREHENSIVE TEST REPORT",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Project: PII De-identification System",
            ""
        ]
        
        # Test results summary
        report_lines.append("🧪 TEST RESULTS:")
        report_lines.append("-" * 40)
        
        for result in self.results.get("tests", []):
            test_type = result["test_type"]
            success = result["success"]
            duration = result["duration"]
            
            status = "✅ PASS" if success else "❌ FAIL"
            report_lines.append(f"{status} {test_type:<20} ({duration:.2f}s)")
            
            total_duration += duration
            if success:
                passed_tests += 1
            else:
                failed_tests += 1
        
        total_tests = passed_tests + failed_tests
        
        # Code Quality summary
        if "code_quality" in self.results:
            report_lines.append("")
            report_lines.append("📝 CODE QUALITY:")
            report_lines.append("-" * 40)
            
            for check, result in self.results["code_quality"].items():
                status = "✅ PASS" if result["success"] else "❌ FAIL"
                report_lines.append(f"{status} {check.upper()}")
        
        # Security scan summary
        if "security_scans" in self.results:
            report_lines.append("")
            report_lines.append("🔒 SECURITY SCANS:")
            report_lines.append("-" * 40)
            
            for scan, result in self.results["security_scans"].items():
                if result["success"]:
                    status = "✅ PASS"
                elif scan == "bandit" and result.get("issues_found"):
                    status = "⚠️  ISSUES FOUND"
                elif scan == "safety" and result.get("vulnerabilities_found"):
                    status = "⚠️  VULNERABILITIES FOUND"
                else:
                    status = "❌ FAIL"
                
                report_lines.append(f"{status} {scan.upper()}")
        
        # Overall summary
        report_lines.extend([
            "",
            "📈 OVERALL SUMMARY:",
            "-" * 40,
            f"Total Tests: {total_tests}",
            f"Passed: {passed_tests}",
            f"Failed: {failed_tests}",
            f"Success Rate: {(passed_tests/total_tests*100):.1f}%" if total_tests > 0 else "N/A",
            f"Total Duration: {total_duration:.2f}s",
            "",
        ])
        
        # Test coverage info
        if os.path.exists("coverage.xml"):
            report_lines.extend([
                "📊 Test coverage report generated: htmlcov/index.html",
                "📄 JUnit XML results: test-results/",
                ""
            ])
        
        # Final verdict
        if failed_tests == 0:
            report_lines.extend([
                "🎉 ALL TESTS PASSED!",
                "✅ System is ready for deployment",
                ""
            ])
        else:
            report_lines.extend([
                f"❌ {failed_tests} TEST(S) FAILED",
                "🚫 Review failures before deployment",
                ""
            ])
        
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)
    
    def save_results(self, filename: str = "test_results.json"):
        """Save test results to JSON file."""
        os.makedirs("test-results", exist_ok=True)
        
        with open(f"test-results/{filename}", "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"📄 Results saved to: test-results/{filename}")


def main():
    """Main test runner entry point."""
    parser = argparse.ArgumentParser(description="PII De-identification System Test Runner")
    parser.add_argument("--test-type", choices=[
        "unit", "integration", "api", "security", "performance", 
        "compliance", "smoke", "all"
    ], default="all", help="Type of tests to run")
    parser.add_argument("--no-coverage", action="store_true", help="Skip coverage reporting")
    parser.add_argument("--no-quality", action="store_true", help="Skip code quality checks")
    parser.add_argument("--no-security", action="store_true", help="Skip security scans")
    parser.add_argument("--quick", action="store_true", help="Run smoke tests only")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Initialize test runner
    runner = TestRunner()
    runner.setup_environment()
    
    print("🚀 Starting Test Execution...")
    print(f"📁 Project Root: {runner.project_root}")
    print(f"🎯 Test Type: {args.test_type}")
    print("")
    
    start_time = time.time()
    
    # Initialize results
    runner.results = {
        "execution_info": {
            "start_time": datetime.now().isoformat(),
            "test_type": args.test_type,
            "arguments": vars(args)
        },
        "tests": []
    }
    
    try:
        # Run tests based on selection
        if args.quick or args.test_type == "smoke":
            result = runner.run_smoke_tests()
            runner.results["tests"].append(result)
        elif args.test_type == "all":
            # Run comprehensive test suite
            test_functions = [
                runner.run_unit_tests,
                runner.run_integration_tests,
                runner.run_api_tests,
                runner.run_security_tests,
                runner.run_performance_tests,
                runner.run_compliance_tests
            ]
            
            for test_func in test_functions:
                result = test_func()
                runner.results["tests"].append(result)
                
                # Print immediate feedback
                status = "✅" if result["success"] else "❌"
                print(f"{status} {result['test_type']} completed in {result['duration']:.2f}s")
        else:
            # Run specific test type
            test_map = {
                "unit": runner.run_unit_tests,
                "integration": runner.run_integration_tests,
                "api": runner.run_api_tests,
                "security": runner.run_security_tests,
                "performance": runner.run_performance_tests,
                "compliance": runner.run_compliance_tests
            }
            
            result = test_map[args.test_type]()
            runner.results["tests"].append(result)
        
        # Run code quality checks
        if not args.no_quality:
            quality_results = runner.run_linting_checks()
            runner.results["code_quality"] = quality_results
        
        # Run security scans
        if not args.no_security:
            security_results = runner.run_security_scans()
            runner.results["security_scans"] = security_results
        
    except KeyboardInterrupt:
        print("\n⏹️  Test execution interrupted by user")
        return 1
    except Exception as e:
        print(f"\n💥 Test execution failed: {e}")
        return 1
    
    # Generate and display report
    end_time = time.time()
    runner.results["execution_info"]["end_time"] = datetime.now().isoformat()
    runner.results["execution_info"]["total_duration"] = end_time - start_time
    
    print("")
    report = runner.generate_summary_report()
    print(report)
    
    # Save results
    runner.save_results()
    
    # Return appropriate exit code
    failed_tests = sum(1 for result in runner.results.get("tests", []) if not result["success"])
    return 1 if failed_tests > 0 else 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)