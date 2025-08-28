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
