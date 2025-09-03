<<<<<<< HEAD
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
=======
# Local AI-Powered PII De-identification System

## Team 404fixed! - Complete Implementation

A production-ready, local AI-powered system for detecting and anonymizing Personally Identifiable Information (PII) in documents using only free and open-source technologies.

## 🚀 Key Features

- **100% Local Operation** - No cloud dependencies or data transmission
- **Multi-Modal PII Detection** - Text + Visual + Context analysis
- **Policy-Driven Architecture** - Configurable for different compliance needs
- **Advanced Anonymization** - Beyond simple redaction
- **Comprehensive Audit Trail** - Complete transparency
- **Mistral 7B Integration** - Intelligent context understanding
- **Multi-Language Support** - English + Hindi optimized for Indian documents

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Interface (FastAPI)                  │
├─────────────────────────────────────────────────────────────┤
│              Local Workflow Orchestrator                    │
│                  (Apache Airflow)                          │
├─────────────────────────────────────────────────────────────┤
│  Document Processing Pipeline                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   OCR       │ │   Layout    │ │  PII NER    │          │
│  │ (Tesseract) │ │(LayoutLMv3) │ │(spaCy+NER)  │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │  Visual PII │ │   Mistral   │ │  Redaction  │          │
│  │  (YOLOv8)   │ │     7B      │ │   Engine    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│              Local Storage & Database                       │
│        (File System + SQLite/PostgreSQL)                   │
└─────────────────────────────────────────────────────────────┘
```

## 🛠️ Technology Stack

### Core Components (All Free)
- **Orchestration**: Apache Airflow
- **Backend API**: FastAPI
- **Database**: SQLite/PostgreSQL
- **Storage**: Local File System
- **Configuration**: JSON/YAML

### AI/ML Models (All Open Source)
- **OCR**: Tesseract + PaddleOCR
- **Layout**: LayoutLMv3
- **NER**: spaCy + Presidio
- **Visual PII**: YOLOv8
- **Context Analysis**: Mistral 7B

## 📋 Quick Start

### Prerequisites
- Python 3.9+
- 8GB+ RAM (16GB recommended)
- RTX 3060 or equivalent GPU (optional but recommended)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd pii-deidentification
   ```

2. **Setup virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup models and database**
   ```bash
   python scripts/setup/install_models.py
   python scripts/setup/init_database.py
   ```

5. **Start services**
   ```bash
   python scripts/deployment/start_services.py
   ```

6. **Access the system**
   - Web Interface: http://localhost:8000
   - Airflow UI: http://localhost:8080
   - API Docs: http://localhost:8000/docs

## 📁 Project Structure

```
pii-deidentification/
├── src/                    # Source code
│   ├── core/              # Core processing logic
│   ├── api/               # FastAPI application
│   ├── cli/               # Command-line interface
│   └── orchestration/     # Airflow workflows
├── frontend/              # React frontend
├── tests/                 # Test suite
├── config/                # Configuration files
├── models/                # AI model storage
├── data/                  # Document storage
├── scripts/               # Setup and maintenance
└── docs/                  # Documentation
```

## 🔧 Configuration

### Environment Variables
Copy `.env.example` to `.env` and configure:
```env
DATABASE_URL=sqlite:///./data/pii_system.db
MODEL_CACHE_DIR=./models/cache
ENABLE_GPU=true
MAX_GPU_MEMORY_MB=6000
```

### Policy Configuration
Configure compliance policies in `config/policies/`:
- HIPAA compliance
- GDPR compliance
- Indian NDHM rules
- Custom policies

## 📊 Success Metrics

- **PII Detection Accuracy**: >95% precision, >90% recall
- **Processing Speed**: <2 minutes per page
- **Supported Formats**: PDF, PNG, JPG, TIFF
- **Languages**: English + Hindi
- **Deployment**: Single-command local setup

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/

# Run with coverage
pytest --cov=src tests/
```

## 🚀 Deployment

### Docker (Recommended)
```bash
docker-compose up -d
```

### Local Development
```bash
python scripts/deployment/start_services.py
```

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [User Guide](docs/USER_GUIDE.md)
- [API Documentation](docs/API_DOCUMENTATION.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Architecture Overview](docs/ARCHITECTURE.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/issues)
- **Documentation**: [Project Wiki](https://github.com/your-repo/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/discussions)

## 🙏 Acknowledgments

- Team 404fixed! for the innovative architecture
- Open source community for the amazing tools
- Contributors and maintainers

---

**Built with ❤️ by Team 404fixed!**
>>>>>>> c8ebce61f799d32c82776b671db0133da2fce30e
