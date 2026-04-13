import React, { useState, useCallback, useEffect } from 'react';
import { motion } from 'motion/react';
import { Upload, FileText, Image, X, Settings, Play, Eye, RefreshCw } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { api } from '../services/api';

interface UploadedFile {
  id: string;
  name: string;
  size: number;
  type: string;
  status: 'pending' | 'uploading' | 'completed' | 'error';
  progress: number;
}

interface Document {
  id: string;
  filename: string;
  file_size: number;
  mime_type: string;
  status: "processing" | "completed" | "failed";
  upload_date: string;
  pii_entities_found?: number;
}

interface FileUploadProps {
  onNavigateToDocuments?: () => void;
}

export function FileUpload({ onNavigateToDocuments }: FileUploadProps) {
  const [files, setFiles] = useState<UploadedFile[]>([]);
  const [recentDocuments, setRecentDocuments] = useState<Document[]>([]);
  const [dragActive, setDragActive] = useState(false);
  const [redactionMethod, setRedactionMethod] = useState('blackout');
  const [outputFormat, setOutputFormat] = useState('same');
  const [detectionSensitivity, setDetectionSensitivity] = useState('high');
  const [isProcessing, setIsProcessing] = useState(false);
  const [loadingDocuments, setLoadingDocuments] = useState(false);

  // Fetch recent documents
  const fetchRecentDocuments = async () => {
    try {
      setLoadingDocuments(true);
      const response = await api.getDocuments();
      if (response.success && response.data) {
        // Show only the 5 most recent documents
        setRecentDocuments(response.data.slice(0, 5));
      }
    } catch (error) {
      console.error('Error fetching documents:', error);
    } finally {
      setLoadingDocuments(false);
    }
  };

  useEffect(() => {
    fetchRecentDocuments();
  }, []);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFiles(Array.from(e.dataTransfer.files));
    }
  }, []);

  const handleFiles = (newFiles: File[]) => {
    const uploadedFiles: UploadedFile[] = newFiles.map((file, index) => ({
      id: `file-${Date.now()}-${index}`,
      name: file.name,
      size: file.size,
      type: file.type,
      status: 'pending',
      progress: 0,
    }));

    setFiles(prev => [...prev, ...uploadedFiles]);

    // Upload files to backend
    uploadedFiles.forEach(async (fileMetadata) => {
      const originalFile = newFiles.find(f => f.name === fileMetadata.name);
      if (!originalFile) return;

      try {
        // Update status to uploading
        setFiles(prev => prev.map(f =>
          f.id === fileMetadata.id ? { ...f, status: 'uploading' } : f
        ));

        // Call API to upload
        const response = await api.uploadDocument(originalFile, {
          redaction_method: redactionMethod as any,
          output_format: outputFormat as any,
          sensitivity: detectionSensitivity as any
        });

        if (response.success) {
          // Update with server response
          setFiles(prev => prev.map(f =>
            f.id === fileMetadata.id ? {
              ...f,
              status: 'completed',
              progress: 100,
              id: response.data?.id || f.id // Use server ID if available
            } : f
          ));
          // Refresh recent documents list
          fetchRecentDocuments();
        } else {
          // Handle error
          setFiles(prev => prev.map(f =>
            f.id === fileMetadata.id ? { ...f, status: 'error', progress: 0 } : f
          ));
          console.error('Upload failed:', response.message);
        }
      } catch (error) {
        // Handle network error
        setFiles(prev => prev.map(f =>
          f.id === fileMetadata.id ? { ...f, status: 'error', progress: 0 } : f
        ));
        console.error('Upload error:', error);
      }
    });
  };

  const removeFile = (id: string) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileIcon = (type: string) => {
    if (type.startsWith('image/')) return Image;
    return FileText;
  };

  const handleProcess = async () => {
    setIsProcessing(true);

    try {
      // Process each uploaded document
      const processPromises = files.map(async (file) => {
        try {
          console.log('🔄 Processing document:', file.id, file.name);

          // Call the process endpoint for this document
          const response = await api.processDocument(file.id, {
            redaction_method: redactionMethod,
            detection_sensitivity: detectionSensitivity,
            output_format: outputFormat
          });

          if (response.success) {
            console.log('✅ Document processed successfully:', file.id);
            return { fileId: file.id, success: true };
          } else {
            console.error('❌ Document processing failed:', file.id, response.message);
            return { fileId: file.id, success: false, error: response.message };
          }
        } catch (error) {
          console.error('❌ Document processing error:', file.id, error);
          return { fileId: file.id, success: false, error: error instanceof Error ? error.message : 'Unknown error' };
        }
      });

      // Wait for all documents to process
      const results = await Promise.all(processPromises);

      const successCount = results.filter(r => r.success).length;
      const failCount = results.filter(r => !r.success).length;

      if (successCount > 0) {
        alert(`Processing completed! ${successCount} document(s) processed successfully${failCount > 0 ? `, ${failCount} failed` : ''}.`);
        // Refresh recent documents list after processing
        fetchRecentDocuments();
      } else {
        alert('Processing failed for all documents. Please check the console for details.');
      }

    } catch (error) {
      console.error('Processing error:', error);
      alert('Processing failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">File Upload</h1>
        <p className="text-slate-600 dark:text-gray-300">Upload documents for PII detection and de-identification</p>
      </motion.div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
        {/* Upload Area */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="xl:col-span-2"
        >
          <Card className="p-6 bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm border-white/20 dark:border-gray-700/30">
            <h2 className="text-xl font-semibold text-slate-900 dark:text-white mb-4">Step 1: Select Files</h2>
            <p className="text-slate-600 dark:text-gray-400 text-sm mb-6">
              Drag and drop files or click to browse. Supported formats: PDF, DOC, DOCX, TXT, JPG, PNG, TIFF
            </p>

            {/* Drop Zone */}
            <div
              className={`border-2 border-dashed rounded-xl p-12 text-center transition-all duration-300 ${
                dragActive
                  ? 'border-blue-500 bg-blue-500/10'
                  : 'border-white/20 hover:border-white/40'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              onClick={() => document.getElementById('file-input')?.click()}
            >
              <motion.div
                animate={dragActive ? { scale: 1.1 } : { scale: 1 }}
                transition={{ duration: 0.2 }}
              >
                <Upload className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <h3 className="text-white text-lg mb-2">Drag & drop files here, or click to select</h3>
                <p className="text-gray-400 text-sm">Maximum file size: 50MB per file</p>
              </motion.div>
            </div>

            <input
              id="file-input"
              type="file"
              multiple
              className="hidden"
              accept=".pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.tiff"
              onChange={(e) => {
                if (e.target.files) {
                  handleFiles(Array.from(e.target.files));
                }
              }}
            />

            {/* File List */}
            {files.length > 0 && (
              <div className="mt-8">
                <h3 className="text-white font-medium mb-4">Uploaded Files ({files.length})</h3>
                <div className="space-y-3">
                  {files.map((file, index) => (
                    <motion.div
                      key={file.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className="flex items-center gap-4 p-4 bg-white/5 rounded-lg border border-white/10"
                    >
                      <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600">
                        {React.createElement(getFileIcon(file.type), { className: "h-5 w-5 text-white" })}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-white font-medium truncate">{file.name}</p>
                        <div className="flex items-center gap-4 mt-1">
                          <p className="text-gray-400 text-sm">{formatFileSize(file.size)}</p>
                          <Badge
                            variant="outline"
                            className={
                              file.status === 'completed'
                                ? 'border-green-500/20 text-green-400 bg-green-500/10'
                                : file.status === 'uploading'
                                ? 'border-blue-500/20 text-blue-400 bg-blue-500/10'
                                : file.status === 'error'
                                ? 'border-red-500/20 text-red-400 bg-red-500/10'
                                : 'border-gray-500/20 text-gray-400 bg-gray-500/10'
                            }
                          >
                            {file.status}
                          </Badge>
                        </div>
                        {file.status === 'uploading' && (
                          <Progress value={file.progress} className="h-2 mt-2" />
                        )}
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeFile(file.id)}
                        className="text-gray-400 hover:text-red-400 hover:bg-red-500/10"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </motion.div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        </motion.div>

        {/* Processing Options */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
            <div className="flex items-center gap-2 mb-4">
              <Settings className="h-5 w-5 text-blue-400" />
              <h2 className="text-xl font-semibold text-white">Processing Options</h2>
            </div>
            <p className="text-gray-400 text-sm mb-6">Configure de-identification settings</p>

            <div className="space-y-6">
              {/* Redaction Method */}
              <div>
                <label className="text-white text-sm mb-2 block">Redaction Method</label>
                <Select value={redactionMethod} onValueChange={setRedactionMethod}>
                  <SelectTrigger className="bg-white/5 border-white/10 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="blackout">Blackout</SelectItem>
                    <SelectItem value="whiteout">Whiteout</SelectItem>
                    <SelectItem value="blur">Blur</SelectItem>
                    <SelectItem value="pixelate">Pixelate</SelectItem>
                    <SelectItem value="replace">Text Replacement</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Output Format */}
              <div>
                <label className="text-white text-sm mb-2 block">Output Format</label>
                <Select value={outputFormat} onValueChange={setOutputFormat}>
                  <SelectTrigger className="bg-white/5 border-white/10 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="same">Same as input</SelectItem>
                    <SelectItem value="pdf">PDF</SelectItem>
                    <SelectItem value="docx">DOCX</SelectItem>
                    <SelectItem value="txt">TXT</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Detection Sensitivity */}
              <div>
                <label className="text-white text-sm mb-2 block">Detection Sensitivity</label>
                <Select value={detectionSensitivity} onValueChange={setDetectionSensitivity}>
                  <SelectTrigger className="bg-white/5 border-white/10 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High (Recommended)</SelectItem>
                    <SelectItem value="maximum">Maximum</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* PII Types */}
              <div>
                <label className="text-white text-sm mb-2 block">PII Detection Types</label>
                <div className="space-y-2 text-gray-300 text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Personal Identifiers (SSN, Passport)
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Contact Information (Email, Phone)
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Financial Data (Credit Cards, Bank)
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Healthcare IDs (MRN, Insurance)
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    Government IDs (Tax ID, License)
                  </div>
                </div>
              </div>

              {/* Actions */}
              <div className="pt-4 space-y-3">
                <Button
                  onClick={handleProcess}
                  disabled={files.length === 0 || isProcessing}
                  className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white"
                >
                  {isProcessing ? (
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                      className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full mr-2"
                    />
                  ) : (
                    <Play className="h-4 w-4 mr-2" />
                  )}
                  {isProcessing ? 'Processing...' : 'Start Processing'}
                </Button>
                
                <Button
                  variant="outline"
                  className="w-full border-white/20 text-white hover:bg-white/10"
                  disabled={files.length === 0}
                  onClick={() => {
                    if (onNavigateToDocuments) {
                      onNavigateToDocuments();
                    }
                  }}
                >
                  <Eye className="h-4 w-4 mr-2" />
                  View All Documents
                </Button>
              </div>
            </div>
          </Card>
        </motion.div>
      </div>

      {/* Recent Documents Section */}
      {recentDocuments.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="mt-8"
        >
          <Card className="p-6 bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm border-white/20 dark:border-gray-700/30">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold text-slate-900 dark:text-white">Recent Documents</h3>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={fetchRecentDocuments}
                  disabled={loadingDocuments}
                  className="gap-2"
                >
                  <RefreshCw className={`h-4 w-4 ${loadingDocuments ? 'animate-spin' : ''}`} />
                  Refresh
                </Button>
                {onNavigateToDocuments && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={onNavigateToDocuments}
                    className="gap-2"
                  >
                    <Eye className="h-4 w-4" />
                    View All
                  </Button>
                )}
              </div>
            </div>

            {loadingDocuments ? (
              <div className="flex items-center justify-center py-8">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                  className="w-6 h-6 border-2 border-teal-500/30 border-t-teal-500 rounded-full mr-3"
                />
                Loading documents...
              </div>
            ) : (
              <div className="space-y-3">
                {recentDocuments.map((doc, index) => (
                  <motion.div
                    key={doc.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.1 }}
                    className="flex items-center gap-4 p-3 bg-white/40 dark:bg-gray-700/40 rounded-xl border border-white/20 dark:border-gray-600/30 hover:bg-white/60 dark:hover:bg-gray-700/60 transition-colors"
                  >
                    <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-teal-400 to-emerald-500 text-white">
                      {React.createElement(doc.mime_type.startsWith('image/') ? Image : FileText, { className: "h-5 w-5" })}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-slate-900 dark:text-white truncate">{doc.filename}</p>
                      <div className="flex items-center gap-3 text-xs text-slate-600 dark:text-gray-400">
                        <span>{(doc.file_size / 1024 / 1024).toFixed(1)} MB</span>
                        <span>{new Date(doc.upload_date).toLocaleDateString()}</span>
                        {doc.pii_entities_found !== undefined && (
                          <span className="text-red-600 dark:text-red-400">
                            {doc.pii_entities_found} PII entities
                          </span>
                        )}
                      </div>
                    </div>
                    <Badge
                      variant="outline"
                      className={
                        doc.status === 'completed'
                          ? 'border-green-500/20 text-green-600 dark:text-green-400'
                          : doc.status === 'processing'
                          ? 'border-blue-500/20 text-blue-600 dark:text-blue-400'
                          : 'border-red-500/20 text-red-600 dark:text-red-400'
                      }
                    >
                      {doc.status}
                    </Badge>
                  </motion.div>
                ))}
              </div>
            )}
          </Card>
        </motion.div>
      )}
    </div>
  );
}