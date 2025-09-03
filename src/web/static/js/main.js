// AI De-identification System - Main JavaScript

// Global variables
let selectedFiles = [];
let processingModal;

// API endpoints
const API_BASE = '/api/v1';
const ENDPOINTS = {
    upload: `${API_BASE}/documents/upload`,
    documents: `${API_BASE}/documents`,
    process: (id) => `${API_BASE}/documents/${id}/process`,
    status: (id) => `${API_BASE}/documents/${id}/processing-status`,
    health: `${API_BASE}/health`
};

// Initialize upload functionality
function initializeUpload() {
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const fileList = document.getElementById('file-list');
    const fileItems = document.getElementById('file-items');
    const clearButton = document.getElementById('clear-files');
    const processButton = document.getElementById('start-processing');

    // Initialize processing modal
    processingModal = new bootstrap.Modal(document.getElementById('processing-modal'));

    // File input change handler
    fileInput.addEventListener('change', function(e) {
        handleFileSelection(e.target.files);
    });

    // Drag and drop handlers
    uploadArea.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        handleFileSelection(e.dataTransfer.files);
    });

    // Click to select files
    uploadArea.addEventListener('click', function() {
        fileInput.click();
    });

    // Clear files button
    clearButton.addEventListener('click', function() {
        selectedFiles = [];
        updateFileList();
    });

    // Start processing button
    processButton.addEventListener('click', function() {
        startProcessing();
    });
}

// Handle file selection
function handleFileSelection(files) {
    const allowedTypes = [
        'application/pdf',
        'image/jpeg',
        'image/jpg', 
        'image/png',
        'image/tiff',
        'text/plain'
    ];

    Array.from(files).forEach(file => {
        // Check file type
        if (!allowedTypes.includes(file.type)) {
            showAlert(`File type "${file.type}" is not supported`, 'warning');
            return;
        }

        // Check file size (100MB limit)
        if (file.size > 100 * 1024 * 1024) {
            showAlert(`File "${file.name}" is too large (max 100MB)`, 'warning');
            return;
        }

        // Check if file already selected
        if (selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
            showAlert(`File "${file.name}" already selected`, 'info');
            return;
        }

        // Add file to selection
        selectedFiles.push(file);
    });

    updateFileList();
}

// Update file list display
function updateFileList() {
    const fileList = document.getElementById('file-list');
    const fileItems = document.getElementById('file-items');
    const clearButton = document.getElementById('clear-files');
    const processButton = document.getElementById('start-processing');

    if (selectedFiles.length === 0) {
        fileList.style.display = 'none';
        clearButton.disabled = true;
        processButton.disabled = true;
        return;
    }

    fileList.style.display = 'block';
    clearButton.disabled = false;
    processButton.disabled = false;

    fileItems.innerHTML = '';

    selectedFiles.forEach((file, index) => {
        const fileItem = createFileItem(file, index);
        fileItems.appendChild(fileItem);
    });
}

// Create file item element
function createFileItem(file, index) {
    const item = document.createElement('div');
    item.className = 'list-group-item d-flex align-items-center';
    item.innerHTML = `
        <i class="bi ${getFileIcon(file.type)} me-3 text-primary"></i>
        <div class="flex-grow-1">
            <div class="fw-medium">${file.name}</div>
            <small class="text-muted">${formatFileSize(file.size)} • ${file.type}</small>
        </div>
        <button type="button" class="btn btn-sm btn-outline-danger" onclick="removeFile(${index})">
            <i class="bi bi-x"></i>
        </button>
    `;
    return item;
}

// Get appropriate file icon
function getFileIcon(fileType) {
    switch (fileType) {
        case 'application/pdf':
            return 'bi-file-earmark-pdf';
        case 'image/jpeg':
        case 'image/jpg':
        case 'image/png':
        case 'image/tiff':
            return 'bi-file-earmark-image';
        case 'text/plain':
            return 'bi-file-earmark-text';
        default:
            return 'bi-file-earmark';
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Remove file from selection
function removeFile(index) {
    selectedFiles.splice(index, 1);
    updateFileList();
}

// Start processing
async function startProcessing() {
    if (selectedFiles.length === 0) {
        showAlert('Please select files to process', 'warning');
        return;
    }

    const policy = document.getElementById('policy-select').value;
    const redactionMethod = document.getElementById('redaction-method').value;

    processingModal.show();
    updateProcessingStatus('Uploading files...', 10);

    try {
        const uploadedDocuments = [];

        // Upload each file
        for (let i = 0; i < selectedFiles.length; i++) {
            const file = selectedFiles[i];
            updateProcessingStatus(`Uploading ${file.name}...`, 10 + (i / selectedFiles.length) * 30);

            const formData = new FormData();
            formData.append('file', file);
            if (policy) formData.append('policy_id', policy);

            const response = await fetch(ENDPOINTS.upload, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`Upload failed: ${await response.text()}`);
            }

            const result = await response.json();
            uploadedDocuments.push(result);
        }

        updateProcessingStatus('Starting document processing...', 50);

        // Start processing for each document
        const processingPromises = uploadedDocuments.map(async (doc, index) => {
            const response = await fetch(ENDPOINTS.process(doc.document_id), {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    policy_id: policy,
                    redaction_method: redactionMethod
                })
            });

            if (!response.ok) {
                throw new Error(`Processing failed for ${doc.filename}`);
            }

            return await response.json();
        });

        const processingResults = await Promise.all(processingPromises);
        updateProcessingStatus('Processing documents...', 70);

        // Monitor processing progress
        await monitorProcessing(uploadedDocuments.map(d => d.document_id));

        // Processing completed
        updateProcessingStatus('Processing completed!', 100);
        
        setTimeout(() => {
            processingModal.hide();
            showProcessingResults(uploadedDocuments);
            selectedFiles = [];
            updateFileList();
        }, 2000);

    } catch (error) {
        console.error('Processing error:', error);
        updateProcessingStatus(`Error: ${error.message}`, 0);
        showAlert(`Processing failed: ${error.message}`, 'danger');
        
        setTimeout(() => {
            processingModal.hide();
        }, 3000);
    }
}

// Monitor processing progress
async function monitorProcessing(documentIds) {
    const maxAttempts = 60; // 5 minutes max
    let attempts = 0;

    return new Promise((resolve, reject) => {
        const checkStatus = async () => {
            attempts++;
            
            try {
                let allCompleted = true;
                let totalProgress = 0;

                for (const docId of documentIds) {
                    const response = await fetch(ENDPOINTS.status(docId));
                    if (!response.ok) {
                        throw new Error(`Status check failed for document ${docId}`);
                    }

                    const status = await response.json();
                    totalProgress += status.progress_percentage;

                    if (status.overall_status === 'failed') {
                        throw new Error(`Processing failed for document ${docId}`);
                    }

                    if (status.overall_status !== 'completed') {
                        allCompleted = false;
                    }
                }

                const avgProgress = Math.round(totalProgress / documentIds.length);
                updateProcessingStatus('Processing documents...', 70 + (avgProgress * 0.3));

                if (allCompleted) {
                    resolve();
                } else if (attempts >= maxAttempts) {
                    reject(new Error('Processing timeout'));
                } else {
                    setTimeout(checkStatus, 5000); // Check every 5 seconds
                }

            } catch (error) {
                reject(error);
            }
        };

        checkStatus();
    });
}

// Update processing modal status
function updateProcessingStatus(message, progress) {
    document.getElementById('processing-status').textContent = message;
    document.getElementById('processing-progress').style.width = `${progress}%`;
    document.getElementById('processing-details').textContent = `${progress}% complete`;
}

// Show processing results
function showProcessingResults(documents) {
    const resultsSection = document.getElementById('results-section');
    const resultsContainer = document.getElementById('processing-results');

    let resultsHtml = '';
    documents.forEach(doc => {
        resultsHtml += `
            <div class="result-item">
                <div class="d-flex align-items-center justify-content-between mb-2">
                    <h6 class="mb-0">
                        <i class="bi bi-file-earmark-check text-success me-2"></i>
                        ${doc.filename}
                    </h6>
                    <span class="badge bg-success">Completed</span>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <small class="text-muted">Original Size: ${formatFileSize(doc.file_size)}</small>
                    </div>
                    <div class="col-md-6">
                        <small class="text-muted">Status: ${doc.status}</small>
                    </div>
                </div>
                <div class="mt-2">
                    <button class="btn btn-sm btn-primary me-2" onclick="downloadDocument('${doc.document_id}', 'original')">
                        <i class="bi bi-download me-1"></i>Download Original
                    </button>
                    <button class="btn btn-sm btn-success" onclick="downloadDocument('${doc.document_id}', 'redacted')">
                        <i class="bi bi-download me-1"></i>Download Redacted
                    </button>
                </div>
            </div>
        `;
    });

    resultsContainer.innerHTML = resultsHtml;
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Download document
async function downloadDocument(documentId, type) {
    try {
        const endpoint = type === 'original' 
            ? `${ENDPOINTS.documents}/${documentId}/download`
            : `${ENDPOINTS.documents}/${documentId}/download-redacted`;

        const response = await fetch(endpoint);
        if (!response.ok) {
            throw new Error('Download failed');
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `document-${type}-${documentId}`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

    } catch (error) {
        showAlert(`Download failed: ${error.message}`, 'danger');
    }
}

// Load system status
async function loadSystemStatus() {
    try {
        const response = await fetch(ENDPOINTS.health);
        const health = await response.json();

        // Update status indicators (simplified for now)
        console.log('System health:', health);
        
    } catch (error) {
        console.error('Failed to load system status:', error);
    }
}

// Load recent activity
async function loadRecentActivity() {
    try {
        const response = await fetch(`${ENDPOINTS.documents}?limit=5`);
        const documents = await response.json();

        const activityContainer = document.getElementById('recent-activity');
        if (documents.length === 0) {
            activityContainer.innerHTML = '<p class="text-muted text-center">No recent activity</p>';
            return;
        }

        let activityHtml = '';
        documents.forEach(doc => {
            const timeAgo = getTimeAgo(new Date(doc.created_at));
            activityHtml += `
                <div class="d-flex align-items-center mb-2">
                    <i class="bi bi-file-earmark text-primary me-2"></i>
                    <div class="flex-grow-1">
                        <small class="fw-medium">${doc.original_filename}</small>
                        <br>
                        <small class="text-muted">${timeAgo}</small>
                    </div>
                    <span class="badge bg-${getStatusColor(doc.status)}">${doc.status}</span>
                </div>
            `;
        });

        activityContainer.innerHTML = activityHtml;

    } catch (error) {
        console.error('Failed to load recent activity:', error);
    }
}

// Utility functions
function getTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);

    if (diffInSeconds < 60) {
        return 'Just now';
    } else if (diffInSeconds < 3600) {
        const minutes = Math.floor(diffInSeconds / 60);
        return `${minutes} min ago`;
    } else if (diffInSeconds < 86400) {
        const hours = Math.floor(diffInSeconds / 3600);
        return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
        const days = Math.floor(diffInSeconds / 86400);
        return `${days} day${days > 1 ? 's' : ''} ago`;
    }
}

function getStatusColor(status) {
    switch (status) {
        case 'completed': return 'success';
        case 'processing': return 'primary';
        case 'failed': return 'danger';
        case 'uploaded': return 'secondary';
        default: return 'secondary';
    }
}

function showAlert(message, type = 'info') {
    const alertContainer = document.createElement('div');
    alertContainer.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertContainer.style.cssText = 'top: 20px; right: 20px; z-index: 1050; max-width: 400px;';
    
    alertContainer.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(alertContainer);
    
    setTimeout(() => {
        if (alertContainer.parentNode) {
            alertContainer.parentNode.removeChild(alertContainer);
        }
    }, 5000);
}