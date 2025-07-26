#!/usr/bin/env python3
"""Test runner script for the project management functionality."""

import sys
import subprocess
from pathlib import Path

def run_tests():
    """Run all project management tests."""
    test_dir = Path(__file__).parent / "tests"
    
    print("🧪 Running Project Management Tests")
    print("=" * 50)
    
    # Run unit tests
    print("\n📦 Unit Tests:")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        str(test_dir / "unit"),
        "-v", "--tb=short"
    ])
    
    if result.returncode != 0:
        print("\n❌ Unit tests failed!")
        return 1
    
    # Run integration tests
    print("\n🔗 Integration Tests:")
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        str(test_dir / "integration"),
        "-v", "--tb=short"
    ])
    
    if result.returncode != 0:
        print("\n❌ Integration tests failed!")
        return 1
    
    print("\n✅ All tests passed!")
    return 0

def run_coverage():
    """Run tests with coverage report."""
    test_dir = Path(__file__).parent / "tests"
    
    print("📊 Running Tests with Coverage")
    print("=" * 50)
    
    result = subprocess.run([
        sys.executable, "-m", "pytest",
        str(test_dir),
        "--cov=src.core.project_manager",
        "--cov=src.core.project_scanner", 
        "--cov=src.core.report_generator",
        "--cov=src.cli.project_commands",
        "--cov=src.cli.client_commands",
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "-v"
    ])
    
    if result.returncode == 0:
        print("\n✅ Coverage report generated in htmlcov/index.html")
    
    return result.returncode

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run project management tests")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage report")
    args = parser.parse_args()
    
    if args.coverage:
        sys.exit(run_coverage())
    else:
        sys.exit(run_tests())