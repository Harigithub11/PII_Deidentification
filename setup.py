#!/usr/bin/env python3
"""
Setup script for PII De-identification System
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="pii-deidentification",
    version="1.0.0",
    author="Team 404fixed!",
    author_email="team@404fixed.com",
    description="Local AI-Powered PII De-identification System",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/404fixed/pii-deidentification",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "pre-commit>=3.3.0",
        ],
        "gpu": [
            "torch>=2.0.0+cu118",
            "torchvision>=0.15.0+cu118",
        ],
    },
    entry_points={
        "console_scripts": [
            "pii-deidentify=cli.main:main",
            "pii-setup=scripts.setup.install_models:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.sql", "*.md"],
    },
    zip_safe=False,
    keywords="pii, deidentification, privacy, ai, ml, ocr, ner, anonymization",
    project_urls={
        "Bug Reports": "https://github.com/404fixed/pii-deidentification/issues",
        "Source": "https://github.com/404fixed/pii-deidentification",
        "Documentation": "https://github.com/404fixed/pii-deidentification/docs",
    },
)
