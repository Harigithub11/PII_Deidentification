# Contributing to Local AI-Powered PII De-identification System

Thank you for your interest in contributing to the Local AI-Powered PII De-identification System! This document provides guidelines and information for contributors.

## 🤝 Code of Conduct

We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful and professional in all interactions.

## 🚀 Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Docker and Docker Compose (recommended)
- Basic understanding of AI/ML, privacy, and data protection concepts

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/yourusername/De-identification-System.git
   cd De-identification-System
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Set Up Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

5. **Run Tests**
   ```bash
   pytest
   ```

## 📋 Development Guidelines

### Code Style

- **Python**: Follow PEP 8 standards
- **Line Length**: Maximum 88 characters (Black formatter standard)
- **Imports**: Use absolute imports, group by standard library, third-party, local
- **Type Hints**: Use type hints for all function parameters and return values
- **Docstrings**: Use Google-style docstrings for all public functions and classes

### Example Code Style

```python
from typing import List, Optional, Dict, Any
from datetime import datetime

class PIIDetector:
    """
    Detects personally identifiable information in text documents.
    
    This class provides methods to identify various types of PII including
    names, email addresses, phone numbers, and social security numbers.
    
    Attributes:
        model_name: Name of the NER model to use
        confidence_threshold: Minimum confidence score for detections
    """
    
    def __init__(self, model_name: str, confidence_threshold: float = 0.8) -> None:
        """Initialize the PII detector.
        
        Args:
            model_name: Name of the NER model
            confidence_threshold: Minimum confidence for valid detections
        """
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
    
    def detect_pii(
        self, 
        text: str, 
        entity_types: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Detect PII entities in the provided text.
        
        Args:
            text: Text content to analyze
            entity_types: Specific entity types to detect (None for all)
            
        Returns:
            List of detected PII entities with confidence scores
            
        Raises:
            ValueError: If text is empty or invalid
        """
        if not text.strip():
            raise ValueError("Text cannot be empty")
        
        # Implementation here
        return []
```

### Commit Guidelines

We follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, no functional changes)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(pii-detection): add support for Hindi language detection

fix(api): resolve memory leak in document processing

docs(readme): update installation instructions

test(security): add comprehensive encryption tests
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions and classes
2. **Integration Tests**: Test component interactions
3. **API Tests**: Test HTTP endpoints
4. **Security Tests**: Test security vulnerabilities
5. **Performance Tests**: Test system performance
6. **Compliance Tests**: Test regulatory compliance

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch
from src.core.services.pii_detector import PIIDetector

class TestPIIDetector:
    """Test suite for PII detection functionality."""
    
    def test_detect_pii_with_valid_text(self):
        """Test PII detection with valid input text."""
        detector = PIIDetector("en_core_web_sm")
        text = "John Smith's email is john.smith@email.com"
        
        results = detector.detect_pii(text)
        
        assert len(results) > 0
        assert any(entity['type'] == 'PERSON' for entity in results)
        assert any(entity['type'] == 'EMAIL' for entity in results)
    
    def test_detect_pii_with_empty_text(self):
        """Test PII detection with empty text should raise ValueError."""
        detector = PIIDetector("en_core_web_sm")
        
        with pytest.raises(ValueError, match="Text cannot be empty"):
            detector.detect_pii("")
    
    @patch('src.core.models.ner_models.spacy.load')
    def test_detect_pii_with_mock_model(self, mock_spacy_load):
        """Test PII detection with mocked spaCy model."""
        mock_model = Mock()
        mock_doc = Mock()
        mock_doc.ents = []
        mock_model.return_value = mock_doc
        mock_spacy_load.return_value = mock_model
        
        detector = PIIDetector("en_core_web_sm")
        results = detector.detect_pii("test text")
        
        assert results == []
        mock_spacy_load.assert_called_once_with("en_core_web_sm")
```

### Test Markers

Use pytest markers to categorize tests:

```python
@pytest.mark.unit
def test_basic_functionality():
    pass

@pytest.mark.integration
@pytest.mark.requires_database
def test_database_integration():
    pass

@pytest.mark.security
def test_encryption_strength():
    pass

@pytest.mark.slow
@pytest.mark.performance
def test_large_document_processing():
    pass
```

## 🔒 Security Guidelines

### Sensitive Data Handling

- Never commit API keys, passwords, or other secrets
- Use environment variables for configuration
- Implement proper input validation
- Follow secure coding practices

### Security Testing

- Test for common vulnerabilities (OWASP Top 10)
- Validate input sanitization
- Test authentication and authorization
- Verify data encryption

## 📝 Documentation Guidelines

### Code Documentation

- Document all public APIs
- Include usage examples
- Explain complex algorithms
- Document security considerations

### User Documentation

- Provide clear installation instructions
- Include configuration examples
- Add troubleshooting guides
- Maintain up-to-date API documentation

## 🐛 Issue Reporting

### Bug Reports

Please include:

1. **Environment Information**
   - Python version
   - Operating system
   - Dependency versions

2. **Reproduction Steps**
   - Clear step-by-step instructions
   - Sample data (anonymized)
   - Expected vs actual behavior

3. **Error Messages**
   - Full error traceback
   - Relevant log entries

### Feature Requests

Please include:

1. **Use Case Description**
   - Problem being solved
   - Target users
   - Business value

2. **Proposed Solution**
   - Detailed feature description
   - API design (if applicable)
   - Implementation considerations

3. **Alternatives Considered**
   - Other approaches evaluated
   - Why this approach is preferred

## 📋 Pull Request Process

### Before Submitting

1. **Code Quality**
   - [ ] Code follows style guidelines
   - [ ] All tests pass
   - [ ] New code is covered by tests
   - [ ] Documentation is updated

2. **Security Review**
   - [ ] No secrets in code
   - [ ] Security implications considered
   - [ ] Compliance requirements met

3. **Performance**
   - [ ] Performance impact assessed
   - [ ] Memory usage considered
   - [ ] Scalability implications evaluated

### PR Description Template

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)  
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Security
- [ ] Security implications reviewed
- [ ] No secrets exposed
- [ ] Compliance requirements met

## Documentation
- [ ] Code comments updated
- [ ] API documentation updated
- [ ] User documentation updated
```

### Review Process

1. **Automated Checks**
   - Code style (Black, flake8)
   - Tests (pytest)
   - Security scan
   - License check

2. **Manual Review**
   - Code quality review
   - Security review
   - Architecture review
   - Documentation review

3. **Approval Requirements**
   - At least one maintainer approval
   - All automated checks pass
   - No unresolved comments

## 🏷️ Release Process

### Versioning

We use Semantic Versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Code Preparation**
   - [ ] All tests pass
   - [ ] Documentation updated
   - [ ] CHANGELOG updated
   - [ ] Version bumped

2. **Security Validation**
   - [ ] Security scan completed
   - [ ] Vulnerability assessment done
   - [ ] Compliance verification

3. **Release Notes**
   - [ ] Feature summary
   - [ ] Bug fixes listed
   - [ ] Breaking changes documented
   - [ ] Migration guide (if needed)

## 🎯 Development Priorities

### Current Focus Areas

1. **Performance Optimization**
   - Model inference speed
   - Memory usage optimization
   - Concurrent processing

2. **Security Enhancements**
   - Advanced threat detection
   - Encryption improvements
   - Audit trail enhancements

3. **Compliance Features**
   - Additional regulatory support
   - Automated compliance checking
   - Enhanced reporting

### Future Roadmap

1. **Q1 2025**: Enhanced AI models and multi-language support
2. **Q2 2025**: Advanced analytics and reporting
3. **Q3 2025**: Enterprise integrations and APIs
4. **Q4 2025**: Cloud-optional deployment options

## 📞 Getting Help

### Resources

- **Documentation**: [docs/](docs/)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **API Reference**: [API Documentation](http://localhost:8000/docs)
- **Security Guide**: [docs/SECURITY.md](docs/SECURITY.md)

### Community

- **GitHub Discussions**: For general questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Security Issues**: Report privately to team404fixed@example.com

### Maintainers

- **Team 404fixed!** - Core team
- Review response time: Within 48 hours
- Issue triage: Weekly

---

Thank you for contributing to making data privacy and PII protection more accessible and effective for everyone! 🛡️

**Last Updated**: January 2025