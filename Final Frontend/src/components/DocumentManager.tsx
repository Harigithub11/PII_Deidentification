import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { FileText, Image, Download, Eye, Trash2, RefreshCw, Calendar, HardDrive, Shield, AlertCircle } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Input } from './ui/input';
import { api } from '../services/api';

interface Document {
  id: string;
  filename: string;
  file_size: number;
  mime_type: string;
  status: "processing" | "completed" | "failed";
  upload_date: string;
  pii_entities_found?: number;
}

interface DocumentPreviewModalProps {
  document: Document | null;
  isOpen: boolean;
  onClose: () => void;
  onDownload: (document: Document) => void;
  downloadingIds: Set<string>;
}

function DocumentPreviewModal({ document, isOpen, onClose, onDownload, downloadingIds }: DocumentPreviewModalProps) {
  const [piiResults, setPiiResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchPII = async () => {
      if (document && isOpen) {
        setLoading(true);
        try {
          const response = await api.getDocumentPII(document.id);
          if (response.success) {
            setPiiResults(response.data || []);
          }
        } catch (error) {
          console.error('Error fetching PII results:', error);
        } finally {
          setLoading(false);
        }
      }
    };

    fetchPII();
  }, [document, isOpen]);

  if (!isOpen || !document) return null;

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.95 }}
        className="bg-white dark:bg-gray-800 rounded-3xl border border-white/20 shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
      >
        {/* Header */}
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-slate-900 dark:text-white">{document.filename}</h2>
              <p className="text-slate-600 dark:text-gray-400 text-sm mt-1">
                PII Detection Results - {piiResults.length} entities found
              </p>
            </div>
            <Button variant="ghost" onClick={onClose} className="rounded-full">
              ×
            </Button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto max-h-[70vh]">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-8 h-8 border-2 border-teal-500/30 border-t-teal-500 rounded-full"
              />
              <span className="ml-3 text-slate-600 dark:text-gray-400">Loading PII results...</span>
            </div>
          ) : piiResults.length > 0 ? (
            <div className="space-y-4">
              {piiResults.map((result, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.1 }}
                  className="p-4 bg-slate-50 dark:bg-gray-700/50 rounded-2xl border border-slate-200 dark:border-gray-600"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <Badge variant="outline" className="bg-red-100 border-red-200 text-red-800 dark:bg-red-900/30 dark:border-red-700 dark:text-red-300">
                          {result.entity_type}
                        </Badge>
                        <span className="text-slate-900 dark:text-white font-mono text-sm bg-white dark:bg-gray-800 px-2 py-1 rounded border">
                          {result.entity_text}
                        </span>
                      </div>
                      <div className="text-xs text-slate-600 dark:text-gray-400">
                        Confidence: {Math.round(result.confidence_score * 100)}% •
                        Position: {result.start_position}-{result.end_position}
                      </div>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Shield className="h-12 w-12 text-green-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">No PII Detected</h3>
              <p className="text-slate-600 dark:text-gray-400">This document appears to be clean of personally identifiable information.</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-white/10 flex justify-between">
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
          <div className="space-x-3">
            <Button
              onClick={() => onDownload(document)}
              disabled={downloadingIds.has(document.id)}
              className="bg-gradient-to-r from-teal-500 to-emerald-600 hover:from-teal-600 hover:to-emerald-700 text-white disabled:opacity-50"
            >
              {downloadingIds.has(document.id) ? (
                <>
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full mr-2"
                  />
                  Downloading...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Download Redacted
                </>
              )}
            </Button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}

export function DocumentManager() {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [previewDocument, setPreviewDocument] = useState<Document | null>(null);
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [downloadingIds, setDownloadingIds] = useState<Set<string>>(new Set());
  const [errorMessage, setErrorMessage] = useState('');

  const fetchDocuments = async () => {
    try {
      setLoading(true);
      const response = await api.getDocuments();
      if (response.success && response.data) {
        setDocuments(response.data);
      }
    } catch (error) {
      console.error('Error fetching documents:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  const filteredDocuments = documents.filter(doc =>
    doc.filename.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getFileIcon = (mimeType: string) => {
    if (mimeType.startsWith('image/')) return Image;
    return FileText;
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge className="bg-green-100 border-green-200 text-green-800 dark:bg-green-900/30 dark:border-green-700 dark:text-green-300">Completed</Badge>;
      case 'processing':
        return <Badge className="bg-blue-100 border-blue-200 text-blue-800 dark:bg-blue-900/30 dark:border-blue-700 dark:text-blue-300">Processing</Badge>;
      case 'failed':
        return <Badge className="bg-red-100 border-red-200 text-red-800 dark:bg-red-900/30 dark:border-red-700 dark:text-red-300">Failed</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const handlePreview = (document: Document) => {
    setPreviewDocument(document);
    setShowPreviewModal(true);
  };

  const handleDownload = async (document: Document) => {
    console.log('🔽 Starting download for document:', document.id, document.filename);

    setDownloadingIds(prev => new Set(prev).add(document.id));
    setErrorMessage('');

    try {
      const response = await api.downloadRedactedDocument(document.id);
      console.log('🔽 Download response status:', response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error('🔽 Download failed:', response.status, errorText);

        let errorMessage = 'Download failed';
        try {
          const errorJson = JSON.parse(errorText);
          errorMessage = errorJson.detail || errorJson.message || errorMessage;
        } catch {
          errorMessage = `Server error: ${response.status}`;
        }

        if (errorMessage.includes('Redacted document not found')) {
          errorMessage = 'Document needs to be redacted first. Please process the document before downloading.';
        }

        setErrorMessage(errorMessage);
        return;
      }

      const blob = await response.blob();
      console.log('🔽 Blob created, size:', blob.size);

      if (blob.size === 0) {
        setErrorMessage('Downloaded file is empty. Please try again.');
        return;
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `redacted_${document.filename}`;
      document.body.appendChild(a);
      a.click();

      // Cleanup
      setTimeout(() => {
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
      }, 100);

      console.log('🔽 Download completed successfully');

    } catch (error) {
      console.error('🔽 Download error:', error);
      setErrorMessage(`Network error: ${error instanceof Error ? error.message : 'Unable to download file'}`);
    } finally {
      setDownloadingIds(prev => {
        const newSet = new Set(prev);
        newSet.delete(document.id);
        return newSet;
      });
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex justify-between items-start"
      >
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Document Manager</h1>
          <p className="text-slate-600 dark:text-gray-300">View and manage your uploaded documents</p>
        </div>
        <Button onClick={fetchDocuments} variant="outline" className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
      </motion.div>

      {/* Search and Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="flex flex-col sm:flex-row gap-4 justify-between"
      >
        <div className="flex-1 max-w-md">
          <Input
            placeholder="Search documents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-white/60 dark:bg-gray-800/60 border-white/20 dark:border-gray-700/30"
          />
        </div>
        <div className="flex gap-6 text-sm">
          <div className="text-center">
            <div className="font-bold text-slate-900 dark:text-white text-lg">{documents.length}</div>
            <div className="text-slate-600 dark:text-gray-400">Total Documents</div>
          </div>
          <div className="text-center">
            <div className="font-bold text-slate-900 dark:text-white text-lg">
              {documents.filter(d => d.status === 'completed').length}
            </div>
            <div className="text-slate-600 dark:text-gray-400">Processed</div>
          </div>
        </div>
      </motion.div>

      {/* Error Message */}
      {errorMessage && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-red-50/80 border border-red-200/60 rounded-2xl p-4"
        >
          <p className="text-red-800 text-sm font-medium">{errorMessage}</p>
          <button
            onClick={() => setErrorMessage('')}
            className="text-red-600 hover:text-red-800 text-xs underline mt-1"
          >
            Dismiss
          </button>
        </motion.div>
      )}

      {/* Document List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="p-6 bg-white/60 dark:bg-gray-800/60 backdrop-blur-sm border-white/20 dark:border-gray-700/30">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-8 h-8 border-2 border-teal-500/30 border-t-teal-500 rounded-full mr-3"
              />
              Loading documents...
            </div>
          ) : filteredDocuments.length > 0 ? (
            <div className="space-y-4">
              {filteredDocuments.map((document, index) => (
                <motion.div
                  key={document.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-center gap-4 p-4 bg-white/40 dark:bg-gray-700/40 rounded-xl border border-white/20 dark:border-gray-600/30 hover:bg-white/60 dark:hover:bg-gray-700/60 transition-colors"
                >
                  {/* File Icon */}
                  <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-teal-400 to-emerald-500 text-white">
                    {React.createElement(getFileIcon(document.mime_type), { className: "h-6 w-6" })}
                  </div>

                  {/* Document Info */}
                  <div className="flex-1 min-w-0">
                    <h3 className="font-medium text-slate-900 dark:text-white truncate">{document.filename}</h3>
                    <div className="flex items-center gap-4 mt-1 text-sm text-slate-600 dark:text-gray-400">
                      <div className="flex items-center gap-1">
                        <HardDrive className="h-3 w-3" />
                        {formatFileSize(document.file_size)}
                      </div>
                      <div className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        {formatDate(document.upload_date)}
                      </div>
                      {document.pii_entities_found !== undefined && (
                        <div className="flex items-center gap-1">
                          <AlertCircle className="h-3 w-3" />
                          {document.pii_entities_found} PII entities
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Status */}
                  <div className="flex items-center gap-3">
                    {getStatusBadge(document.status)}
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handlePreview(document)}
                      className="h-8 w-8 p-0"
                      disabled={document.status !== 'completed'}
                    >
                      <Eye className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleDownload(document)}
                      className="h-8 w-8 p-0"
                      disabled={document.status !== 'completed' || downloadingIds.has(document.id)}
                    >
                      {downloadingIds.has(document.id) ? (
                        <motion.div
                          animate={{ rotate: 360 }}
                          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                          className="w-4 h-4 border-2 border-slate-400/30 border-t-slate-600 rounded-full"
                        />
                      ) : (
                        <Download className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </motion.div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-slate-900 dark:text-white mb-2">No Documents Found</h3>
              <p className="text-slate-600 dark:text-gray-400">
                {searchTerm ? 'No documents match your search.' : 'Upload your first document to get started.'}
              </p>
            </div>
          )}
        </Card>
      </motion.div>

      {/* Preview Modal */}
      <DocumentPreviewModal
        document={previewDocument}
        isOpen={showPreviewModal}
        onClose={() => {
          setShowPreviewModal(false);
          setPreviewDocument(null);
        }}
        onDownload={handleDownload}
        downloadingIds={downloadingIds}
      />
    </div>
  );
}