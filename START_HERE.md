# 🚀 Quick Start Guide - Multi-Format Document API

## Prerequisites

1. **Python 3.9+** installed
2. **Virtual environment** (recommended)

## Installation & Setup

### 1. Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt
```

### 2. Start the API Server

```bash
# Start the FastAPI server
python run_server.py
```

The server will start at: **http://localhost:8000**

## 🧪 Testing the API

### Option 1: Automated Test Suite

Run the comprehensive test script that tests all supported formats:

```bash
python test_api.py
```

This will:
- ✅ Test API health
- ✅ Get supported formats
- ✅ Test PDF processing
- ✅ Test all image formats (PNG, JPG, JPEG, TIFF, BMP, WebP)
- ✅ Generate test documents automatically
- ✅ Monitor processing status
- ✅ Show detailed results

### Option 2: Manual API Testing

#### Using curl:

```bash
# 1. Check API health
curl http://localhost:8000/health

# 2. Get supported formats
curl http://localhost:8000/api/v1/documents/formats

# 3. Upload a document (replace with your file)
curl -X POST "http://localhost:8000/api/v1/documents/upload" \
     -F "file=@sample.pdf" \
     -F "auto_process=true"

# 4. Check document status (use document_id from step 3)
curl http://localhost:8000/api/v1/documents/status/{document_id}

# 5. Get processing results
curl http://localhost:8000/api/v1/documents/results/{document_id}
```

#### Using Browser:

1. **API Documentation**: http://localhost:8000/docs
2. **Alternative Docs**: http://localhost:8000/redoc
3. **Root Page**: http://localhost:8000/

## 📄 Supported Formats

### PDFs
- ✅ Multi-page documents
- ✅ Text extraction
- ✅ Image extraction
- ✅ Scanned PDF optimization

### Images
- ✅ PNG, JPG, JPEG
- ✅ TIFF, TIF, BMP
- ✅ WebP, GIF
- ✅ Quality enhancement
- ✅ OCR preparation

### Processing Features
- 🔄 **Background processing** with job tracking
- 📊 **Quality assessment** and metrics
- 🛠️ **Automatic format detection**
- 🖼️ **Scanned document optimization**
- 📝 **Text extraction preview**
- ⚡ **Memory-efficient processing**

## 🎯 Example Test Workflow

1. **Start the server**: `python run_server.py`
2. **Run automated tests**: `python test_api.py`
3. **Check results** in the console output
4. **Visit** http://localhost:8000/docs for interactive testing

## 🔧 API Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/documents/upload` | POST | Upload & process documents |
| `/api/v1/documents/status/{id}` | GET | Get processing status |
| `/api/v1/documents/results/{id}` | GET | Get processing results |
| `/api/v1/documents/formats` | GET | Get supported formats |
| `/api/v1/documents/job/{job_id}` | GET | Get job status |

## 🐛 Troubleshooting

### Common Issues:

1. **ImportError**: Install missing dependencies
   ```bash
   pip install -r requirements.txt
   ```

2. **Port already in use**: Change port in `run_server.py`

3. **Processing fails**: Check logs in console output

4. **Large files timeout**: Increase timeout values in API

### Debug Mode:

The server runs with auto-reload enabled for development. Check console logs for detailed error information.

## 📊 Expected Test Results

When running `test_api.py`, you should see:
- ✅ API Health Check: PASSED
- ✅ All format uploads successful
- ✅ Background processing completed
- ✅ Quality scores and processing metrics
- ✅ Text extraction previews
- 🎉 All tests passed!

Ready to test! 🚀