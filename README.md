# AI-Powered De-identification System

A comprehensive, self-hosted solution for automatically detecting and redacting personally identifiable information (PII) from mixed-format documents including PDFs, images, and scanned files.

## 🎯 Project Overview

This system addresses critical data privacy needs by providing:
- **Textual PII Detection**: Microsoft Presidio integration for robust text analysis
- **Visual PII Detection**: YOLOv8 for faces, signatures, and stamps (Phase 3)
- **Self-Hosted Architecture**: Complete data sovereignty with Docker containerization
- **Enterprise Compliance**: HIPAA, GDPR, and PCI DSS compliance features

## 🏗️ Architecture

```
ai-deidentification/
├── src/
│   ├── api/           # FastAPI application and routes
│   ├── core/          # Core business logic and PII detection
│   ├── models/        # Database models and schemas
│   ├── services/      # External service integrations (OCR, Presidio)
│   ├── utils/         # Utility functions and helpers
│   └── web/           # Web interface templates and static files
├── tests/             # Unit and integration tests
├── config/            # Configuration files
├── docs/              # Documentation and API specs
├── scripts/           # Deployment and utility scripts
└── data/              # Data directories (input/output/temp)
```

## 📋 Development Phases

### Phase 0: Environment Setup ✅
- System requirements verification
- Core tools installation
- Project structure creation

### Phase 1: MVP Core Infrastructure (Days 1-2)
- PostgreSQL database setup
- FastAPI application framework
- File upload system
- OCR integration (Tesseract)

### Phase 2: Textual PII Detection (Days 2-3)
- Microsoft Presidio integration
- Text processing pipeline
- Redaction engine

### Phase 3: Web Interface (Days 3-4)
- Frontend development
- Processing dashboard
- Results management

## 🔧 System Requirements

- **Memory**: 16GB RAM minimum
- **Storage**: 1TB available space
- **GPU**: NVIDIA RTX 3060 (for Phase 3 visual processing)
- **OS**: Windows 10/11, Ubuntu 20.04+, macOS 10.15+

## 🚀 Quick Start

```bash
# Clone and setup
git clone <repository-url>
cd ai-deidentification

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start services
docker-compose up -d

# Run application
python src/api/main.py
```

## 📊 Success Metrics (MVP)

- Process 95% of text-based documents without manual intervention
- Sub-30-second processing time for typical business documents
- 99.9% uptime during continuous operation
- 90%+ precision and recall for common PII types

## 🔒 Privacy & Security

- **Zero Trust Architecture**: All processing within user-controlled environment
- **No External Dependencies**: Complete offline operation capability
- **Audit Trail**: Comprehensive logging of all operations
- **Data Encryption**: At-rest and in-transit protection

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Status**: 🚧 Under Development  
**Current Phase**: Phase 0 - Environment Setup  
**Next Milestone**: MVP Core Infrastructure