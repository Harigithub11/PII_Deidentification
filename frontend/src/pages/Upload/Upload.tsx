import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Button,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Chip,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Grid,
  Stepper,
  Step,
  StepLabel,
  useTheme,
  alpha,
} from '@mui/material';
import {
  CloudUpload as UploadIcon,
  InsertDriveFile as FileIcon,
  Delete as DeleteIcon,
  Settings as SettingsIcon,
  PlayArrow as StartIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Visibility as PreviewIcon,
} from '@mui/icons-material';
import { useUIStore } from '@store/uiStore';
import { api } from '@services/api';
import { BatchJobConfig, FileUpload, PolicyConfiguration } from '@types/index';

interface UploadFile extends File {
  id: string;
  uploadProgress?: number;
  uploadStatus?: 'pending' | 'uploading' | 'completed' | 'failed';
  preview?: string;
}

const Upload: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { addNotification } = useUIStore();

  const [activeStep, setActiveStep] = useState(0);
  const [files, setFiles] = useState<UploadFile[]>([]);
  const [uploading, setUploading] = useState(false);
  const [jobConfig, setJobConfig] = useState<BatchJobConfig>({
    name: '',
    job_type: 'document_processing',
    priority: 'medium',
    policy_id: '',
    settings: {
      output_format: 'pdf',
      redaction_method: 'blackout',
      preserve_formatting: true,
      include_confidence_scores: false,
    }
  });
  const [policies, setPolicies] = useState<PolicyConfiguration[]>([]);
  const [previewFile, setPreviewFile] = useState<UploadFile | null>(null);
  const [previewDialogOpen, setPreviewDialogOpen] = useState(false);

  const steps = ['Select Files', 'Configure Job', 'Review & Start'];

  React.useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      const response = await api.get<PolicyConfiguration[]>('/policies/');
      setPolicies(response.data || []);
      if (response.data && response.data.length > 0) {
        setJobConfig(prev => ({ ...prev, policy_id: response.data![0].id }));
      }
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Policies Error',
        message: 'Failed to load policies'
      });
    }
  };

  const onDrop = useCallback((acceptedFiles: File[], rejectedFiles: any[]) => {
    if (rejectedFiles.length > 0) {
      addNotification({
        type: 'error',
        title: 'Invalid Files',
        message: `${rejectedFiles.length} files were rejected. Please check file type and size limits.`
      });
    }

    const newFiles: UploadFile[] = acceptedFiles.map(file => ({
      ...file,
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      uploadStatus: 'pending',
      preview: file.type.startsWith('image/') ? URL.createObjectURL(file) : undefined,
    }));

    setFiles(prev => [...prev, ...newFiles]);
  }, [addNotification]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/msword': ['.doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
      'text/plain': ['.txt'],
      'image/jpeg': ['.jpg', '.jpeg'],
      'image/png': ['.png'],
      'image/tiff': ['.tiff', '.tif'],
    },
    maxSize: 50 * 1024 * 1024, // 50MB
    multiple: true,
  });

  const removeFile = (fileId: string) => {
    setFiles(prev => prev.filter(file => file.id !== fileId));
  };

  const uploadFiles = async () => {
    if (files.length === 0) return;

    setUploading(true);

    try {
      // Update all files to uploading status
      setFiles(prev => prev.map(file => ({ ...file, uploadStatus: 'uploading' as const })));

      // Upload files one by one
      const uploadedFiles: FileUpload[] = [];
      
      for (const file of files) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
          // Simulate progress updates
          const progressInterval = setInterval(() => {
            setFiles(prev => prev.map(f => 
              f.id === file.id 
                ? { ...f, uploadProgress: Math.min((f.uploadProgress || 0) + 20, 90) }
                : f
            ));
          }, 200);

          const response = await api.post<FileUpload>('/files/upload', formData);

          clearInterval(progressInterval);
          
          uploadedFiles.push(response.data);
          
          setFiles(prev => prev.map(f => 
            f.id === file.id 
              ? { ...f, uploadProgress: 100, uploadStatus: 'completed' as const }
              : f
          ));

        } catch (error) {
          setFiles(prev => prev.map(f => 
            f.id === file.id 
              ? { ...f, uploadStatus: 'failed' as const }
              : f
          ));
          throw error;
        }
      }

      // Create batch job
      const jobData = {
        ...jobConfig,
        file_ids: uploadedFiles.map(f => f.id),
      };

      const jobResponse = await api.post('/jobs/', jobData);

      addNotification({
        type: 'success',
        title: 'Job Created',
        message: `Job "${jobConfig.name}" created successfully`
      });

      navigate(`/jobs/${(jobResponse.data as any)?.id}`);

    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Upload Failed',
        message: 'Failed to upload files or create job'
      });
    } finally {
      setUploading(false);
    }
  };

  const handleNext = () => {
    if (activeStep === 0 && files.length === 0) {
      addNotification({
        type: 'warning',
        title: 'No Files',
        message: 'Please select at least one file to continue'
      });
      return;
    }

    if (activeStep === 1 && !jobConfig.name.trim()) {
      addNotification({
        type: 'warning',
        title: 'Job Name Required',
        message: 'Please enter a job name to continue'
      });
      return;
    }

    setActiveStep(prev => prev + 1);
  };

  const handleBack = () => {
    setActiveStep(prev => prev - 1);
  };

  const getFileIcon = (file: UploadFile) => {
    if (file.type.startsWith('image/')) return '🖼️';
    if (file.type.includes('pdf')) return '📄';
    if (file.type.includes('word')) return '📝';
    if (file.type.includes('text')) return '📄';
    return '📁';
  };

  const getFileStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckIcon color="success" />;
      case 'failed': return <ErrorIcon color="error" />;
      case 'uploading': return <LinearProgress sx={{ width: 100 }} />;
      default: return <FileIcon />;
    }
  };

  return (
    <Box>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        Upload Documents
      </Typography>

      <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
        {steps.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {/* Step 1: File Selection */}
      {activeStep === 0 && (
        <Box>
          <Paper
            {...getRootProps()}
            sx={{
              p: 4,
              mb: 3,
              textAlign: 'center',
              border: `2px dashed ${isDragActive ? theme.palette.primary.main : theme.palette.divider}`,
              backgroundColor: isDragActive ? alpha(theme.palette.primary.main, 0.04) : 'transparent',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              '&:hover': {
                backgroundColor: alpha(theme.palette.primary.main, 0.04),
                borderColor: theme.palette.primary.main,
              }
            }}
          >
            <input {...getInputProps()} />
            <UploadIcon sx={{ fontSize: 64, color: 'primary.main', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              {isDragActive ? 'Drop files here...' : 'Drag & drop files here, or click to browse'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Supports PDF, DOC, DOCX, TXT, JPG, PNG, TIFF (max 50MB per file)
            </Typography>
          </Paper>

          {files.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>
                Selected Files ({files.length})
              </Typography>
              <List>
                {files.map((file) => (
                  <ListItem key={file.id}>
                    <ListItemIcon>
                      {getFileStatusIcon(file.uploadStatus || 'pending')}
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <span>{getFileIcon(file)}</span>
                          <span>{file.name}</span>
                          <Chip 
                            label={`${(file.size / 1024 / 1024).toFixed(2)} MB`} 
                            size="small" 
                            variant="outlined" 
                          />
                        </Box>
                      }
                      secondary={
                        file.uploadProgress !== undefined ? (
                          <LinearProgress 
                            variant="determinate" 
                            value={file.uploadProgress} 
                            sx={{ mt: 1 }}
                          />
                        ) : null
                      }
                    />
                    <ListItemSecondaryAction>
                      {file.preview && (
                        <IconButton 
                          onClick={() => {
                            setPreviewFile(file);
                            setPreviewDialogOpen(true);
                          }}
                          size="small"
                        >
                          <PreviewIcon />
                        </IconButton>
                      )}
                      <IconButton 
                        onClick={() => removeFile(file.id)} 
                        size="small"
                        disabled={uploading}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Box>
      )}

      {/* Step 2: Job Configuration */}
      {activeStep === 1 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  <SettingsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Job Settings
                </Typography>
                
                <TextField
                  fullWidth
                  label="Job Name"
                  value={jobConfig.name}
                  onChange={(e) => setJobConfig(prev => ({ ...prev, name: e.target.value }))}
                  margin="normal"
                  required
                />

                <FormControl fullWidth margin="normal">
                  <InputLabel>Job Type</InputLabel>
                  <Select
                    value={jobConfig.job_type}
                    onChange={(e) => setJobConfig(prev => ({ ...prev, job_type: e.target.value }))}
                    label="Job Type"
                  >
                    <MenuItem value="document_processing">Document Processing</MenuItem>
                    <MenuItem value="image_processing">Image Processing</MenuItem>
                    <MenuItem value="batch_redaction">Batch Redaction</MenuItem>
                  </Select>
                </FormControl>

                <FormControl fullWidth margin="normal">
                  <InputLabel>Priority</InputLabel>
                  <Select
                    value={jobConfig.priority}
                    onChange={(e) => setJobConfig(prev => ({ ...prev, priority: e.target.value }))}
                    label="Priority"
                  >
                    <MenuItem value="low">Low</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                  </Select>
                </FormControl>

                <FormControl fullWidth margin="normal">
                  <InputLabel>Policy</InputLabel>
                  <Select
                    value={jobConfig.policy_id}
                    onChange={(e) => setJobConfig(prev => ({ ...prev, policy_id: e.target.value }))}
                    label="Policy"
                  >
                    {policies.map((policy) => (
                      <MenuItem key={policy.id} value={policy.id}>
                        {policy.name}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Processing Options
                </Typography>

                <FormControl fullWidth margin="normal">
                  <InputLabel>Output Format</InputLabel>
                  <Select
                    value={jobConfig.settings.output_format}
                    onChange={(e) => setJobConfig(prev => ({
                      ...prev,
                      settings: { ...prev.settings, output_format: e.target.value }
                    }))}
                    label="Output Format"
                  >
                    <MenuItem value="pdf">PDF</MenuItem>
                    <MenuItem value="docx">Word Document</MenuItem>
                    <MenuItem value="txt">Text</MenuItem>
                  </Select>
                </FormControl>

                <FormControl fullWidth margin="normal">
                  <InputLabel>Redaction Method</InputLabel>
                  <Select
                    value={jobConfig.settings.redaction_method}
                    onChange={(e) => setJobConfig(prev => ({
                      ...prev,
                      settings: { ...prev.settings, redaction_method: e.target.value }
                    }))}
                    label="Redaction Method"
                  >
                    <MenuItem value="blackout">Black Box</MenuItem>
                    <MenuItem value="replacement">Text Replacement</MenuItem>
                    <MenuItem value="blur">Blur</MenuItem>
                  </Select>
                </FormControl>

                <Alert severity="info" sx={{ mt: 2 }}>
                  Files will be processed according to the selected policy configuration.
                </Alert>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Step 3: Review */}
      {activeStep === 2 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Job Summary
                </Typography>
                <Box sx={{ mb: 2 }}>
                  <Typography variant="body1"><strong>Name:</strong> {jobConfig.name}</Typography>
                  <Typography variant="body1"><strong>Type:</strong> {jobConfig.job_type}</Typography>
                  <Typography variant="body1"><strong>Priority:</strong> {jobConfig.priority}</Typography>
                  <Typography variant="body1"><strong>Files:</strong> {files.length}</Typography>
                </Box>
                
                <Typography variant="h6" gutterBottom>
                  Files to Process
                </Typography>
                <List dense>
                  {files.map((file) => (
                    <ListItem key={file.id}>
                      <ListItemText 
                        primary={file.name}
                        secondary={`${(file.size / 1024 / 1024).toFixed(2)} MB`}
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Alert severity="info">
              Once started, this job will process all selected files according to your configuration. 
              You can monitor progress from the Jobs page.
            </Alert>
          </Grid>
        </Grid>
      )}

      {/* Navigation Buttons */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
        <Button
          disabled={activeStep === 0}
          onClick={handleBack}
        >
          Back
        </Button>
        
        <Box sx={{ display: 'flex', gap: 2 }}>
          {activeStep < steps.length - 1 ? (
            <Button variant="contained" onClick={handleNext}>
              Next
            </Button>
          ) : (
            <Button
              variant="contained"
              startIcon={<StartIcon />}
              onClick={uploadFiles}
              disabled={uploading || files.length === 0}
            >
              {uploading ? 'Starting Job...' : 'Start Processing'}
            </Button>
          )}
        </Box>
      </Box>

      {/* File Preview Dialog */}
      <Dialog
        open={previewDialogOpen}
        onClose={() => setPreviewDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          File Preview: {previewFile?.name}
        </DialogTitle>
        <DialogContent>
          {previewFile?.preview && (
            <Box sx={{ textAlign: 'center' }}>
              <img
                src={previewFile.preview}
                alt="File preview"
                style={{ maxWidth: '100%', maxHeight: '400px' }}
              />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPreviewDialogOpen(false)}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Upload;