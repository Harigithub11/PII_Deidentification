import React, { useEffect, useState } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  IconButton,
  Chip,
  TextField,
  InputAdornment,
  Menu,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  LinearProgress,
  Fab,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Search as SearchIcon,
  Add as AddIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  Stop as StopIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  MoreVert as MoreIcon,
} from '@mui/icons-material';
import { useUIStore } from '@store/uiStore';
import { api } from '@services/api';
import { websocketService } from '@services/websocket';
import { BatchJob, JobFilter } from '@types/index';

const Jobs: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const { addNotification } = useUIStore();

  const [jobs, setJobs] = useState<BatchJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [totalJobs, setTotalJobs] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [filters] = useState<JobFilter>({});
  const [selectedJob, setSelectedJob] = useState<BatchJob | null>(null);
  const [actionMenuAnchor, setActionMenuAnchor] = useState<null | HTMLElement>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [jobToDelete, setJobToDelete] = useState<BatchJob | null>(null);

  useEffect(() => {
    loadJobs();

    // Subscribe to real-time job updates
    const unsubscribe = websocketService.subscribeToJobs((data) => {
      if (data.type === 'job_status_update') {
        setJobs(prevJobs => 
          prevJobs.map(job => 
            job.id === data.job_id 
              ? { ...job, status: data.status, progress_percentage: data.progress_percentage }
              : job
          )
        );
      } else if (data.type === 'new_job') {
        loadJobs(); // Reload to get the new job
      }
    });

    return () => {
      unsubscribe();
    };
  }, [page, rowsPerPage, searchQuery, filters]);

  const loadJobs = async () => {
    setLoading(true);
    try {
      const params = {
        page: page + 1,
        page_size: rowsPerPage,
        search: searchQuery || undefined,
        ...filters,
      };

      const response = await api.get<{
        jobs: BatchJob[];
        total: number;
        page: number;
        page_size: number;
      }>('/jobs/', params);

      setJobs(response.data?.jobs || []);
      setTotalJobs(response.data?.total || 0);
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Jobs Error',
        message: 'Failed to load jobs'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleJobAction = async (jobId: string, action: 'start' | 'pause' | 'stop' | 'restart') => {
    try {
      await api.post(`/jobs/${jobId}/${action}`);
      addNotification({
        type: 'success',
        title: 'Job Action',
        message: `Job ${action}ed successfully`
      });
      loadJobs();
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Job Action Failed',
        message: `Failed to ${action} job`
      });
    }
  };

  const handleDeleteJob = async () => {
    if (!jobToDelete) return;

    try {
      await api.delete(`/jobs/${jobToDelete.id}`);
      addNotification({
        type: 'success',
        title: 'Job Deleted',
        message: 'Job deleted successfully'
      });
      setDeleteDialogOpen(false);
      setJobToDelete(null);
      loadJobs();
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Delete Failed',
        message: 'Failed to delete job'
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return theme.palette.success.main;
      case 'running': return theme.palette.primary.main;
      case 'failed': return theme.palette.error.main;
      case 'pending': return theme.palette.warning.main;
      case 'paused': return theme.palette.info.main;
      default: return theme.palette.grey[500];
    }
  };

  const getStatusChip = (status: string) => (
    <Chip
      label={status.charAt(0).toUpperCase() + status.slice(1)}
      size="small"
      sx={{
        backgroundColor: alpha(getStatusColor(status), 0.1),
        color: getStatusColor(status),
        fontWeight: 'medium',
      }}
    />
  );

  const getPriorityChip = (priority: string) => {
    const colors = {
      high: theme.palette.error.main,
      medium: theme.palette.warning.main,
      low: theme.palette.info.main,
    };

    return (
      <Chip
        label={priority.charAt(0).toUpperCase() + priority.slice(1)}
        size="small"
        sx={{
          backgroundColor: alpha(colors[priority as keyof typeof colors] || colors.low, 0.1),
          color: colors[priority as keyof typeof colors] || colors.low,
          fontWeight: 'medium',
        }}
      />
    );
  };

  const handleActionMenuOpen = (event: React.MouseEvent<HTMLElement>, job: BatchJob) => {
    setActionMenuAnchor(event.currentTarget);
    setSelectedJob(job);
  };

  const handleActionMenuClose = () => {
    setActionMenuAnchor(null);
    setSelectedJob(null);
  };

  return (
    <Routes>
      <Route path="/" element={
        <Box>
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h4" fontWeight="bold">
              Batch Processing Jobs
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => navigate('/upload')}
            >
              New Job
            </Button>
          </Box>

          {/* Search and Filters */}
          <Paper sx={{ p: 2, mb: 3 }}>
            <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
              <TextField
                placeholder="Search jobs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                }}
                sx={{ minWidth: 300 }}
              />
              <IconButton onClick={loadJobs}>
                <RefreshIcon />
              </IconButton>
            </Box>
          </Paper>

          {/* Jobs Table */}
          <Paper>
            <TableContainer>
              {loading && <LinearProgress />}
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Job Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Priority</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>Duration</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {jobs.map((job) => (
                    <TableRow key={job.id} hover>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {job.name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {job.id}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {job.job_type}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {getStatusChip(job.status)}
                      </TableCell>
                      <TableCell>
                        {getPriorityChip(job.priority)}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 120 }}>
                          <LinearProgress
                            variant="determinate"
                            value={job.progress_percentage}
                            sx={{ flex: 1 }}
                          />
                          <Typography variant="body2" color="text.secondary">
                            {job.progress_percentage}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(job.created_at).toLocaleDateString()}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(job.created_at).toLocaleTimeString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {job.duration_seconds ? `${Math.round(job.duration_seconds / 60)}m` : '-'}
                        </Typography>
                      </TableCell>
                      <TableCell align="center">
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          <IconButton 
                            size="small" 
                            onClick={() => navigate(`/jobs/${job.id}`)}
                            title="View Details"
                          >
                            <ViewIcon fontSize="small" />
                          </IconButton>
                          {job.status === 'pending' || job.status === 'paused' ? (
                            <IconButton 
                              size="small" 
                              onClick={() => handleJobAction(job.id, 'start')}
                              title="Start Job"
                            >
                              <PlayIcon fontSize="small" />
                            </IconButton>
                          ) : job.status === 'running' ? (
                            <IconButton 
                              size="small" 
                              onClick={() => handleJobAction(job.id, 'pause')}
                              title="Pause Job"
                            >
                              <PauseIcon fontSize="small" />
                            </IconButton>
                          ) : null}
                          <IconButton
                            size="small"
                            onClick={(e) => handleActionMenuOpen(e, job)}
                            title="More Actions"
                          >
                            <MoreIcon fontSize="small" />
                          </IconButton>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              rowsPerPageOptions={[5, 10, 25, 50]}
              component="div"
              count={totalJobs}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={(_, newPage) => setPage(newPage)}
              onRowsPerPageChange={(e) => {
                setRowsPerPage(parseInt(e.target.value, 10));
                setPage(0);
              }}
            />
          </Paper>

          {/* Floating Action Button */}
          <Fab
            color="primary"
            aria-label="add job"
            sx={{ position: 'fixed', bottom: 16, right: 16 }}
            onClick={() => navigate('/upload')}
          >
            <AddIcon />
          </Fab>

          {/* Action Menu */}
          <Menu
            anchorEl={actionMenuAnchor}
            open={Boolean(actionMenuAnchor)}
            onClose={handleActionMenuClose}
          >
            <MenuItem onClick={() => { 
              if (selectedJob) navigate(`/jobs/${selectedJob.id}`);
              handleActionMenuClose();
            }}>
              <ViewIcon sx={{ mr: 1 }} fontSize="small" />
              View Details
            </MenuItem>
            {selectedJob?.status === 'completed' && (
              <MenuItem onClick={() => {
                // Handle download
                handleActionMenuClose();
              }}>
                <DownloadIcon sx={{ mr: 1 }} fontSize="small" />
                Download Results
              </MenuItem>
            )}
            {selectedJob?.status === 'failed' && (
              <MenuItem onClick={() => {
                if (selectedJob) handleJobAction(selectedJob.id, 'restart');
                handleActionMenuClose();
              }}>
                <PlayIcon sx={{ mr: 1 }} fontSize="small" />
                Restart Job
              </MenuItem>
            )}
            <MenuItem 
              onClick={() => {
                setJobToDelete(selectedJob);
                setDeleteDialogOpen(true);
                handleActionMenuClose();
              }}
              sx={{ color: 'error.main' }}
            >
              <DeleteIcon sx={{ mr: 1 }} fontSize="small" />
              Delete Job
            </MenuItem>
          </Menu>

          {/* Delete Confirmation Dialog */}
          <Dialog
            open={deleteDialogOpen}
            onClose={() => setDeleteDialogOpen(false)}
          >
            <DialogTitle>Delete Job</DialogTitle>
            <DialogContent>
              <Typography>
                Are you sure you want to delete the job "{jobToDelete?.name}"? This action cannot be undone.
              </Typography>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDeleteDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleDeleteJob} color="error" variant="contained">
                Delete
              </Button>
            </DialogActions>
          </Dialog>
        </Box>
      } />
      {/* Job detail route would be handled here */}
    </Routes>
  );
};

export default Jobs;