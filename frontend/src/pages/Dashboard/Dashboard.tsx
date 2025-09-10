import React, { useEffect, useState } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  LinearProgress,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  useTheme,
  alpha,
} from '@mui/material';
import {
  PlayArrow as StartIcon,
  Pause as PauseIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  Assignment as JobsIcon,
  CloudUpload as UploadIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useAuthStore } from '@store/authStore';
import { useUIStore } from '@store/uiStore';
import { api } from '@services/api';
import { websocketService } from '@services/websocket';
import { DashboardStats, BatchJob, RecentActivity } from '@types/index';

const Dashboard: React.FC = () => {
  const theme = useTheme();
  const { user } = useAuthStore();
  const { addNotification } = useUIStore();
  
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentJobs, setRecentJobs] = useState<BatchJob[]>([]);
  const [recentActivity, setRecentActivity] = useState<RecentActivity[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
    
    // Subscribe to real-time updates
    const unsubscribe = websocketService.subscribeToDashboard('main', (data) => {
      if (data.type === 'stats_update') {
        setStats(data.stats);
      } else if (data.type === 'job_update') {
        loadRecentJobs();
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  const loadDashboardData = async () => {
    try {
      const [statsResponse, jobsResponse, activityResponse] = await Promise.all([
        api.get<DashboardStats>('/dashboard/stats'),
        api.get<BatchJob[]>('/jobs/recent'),
        api.get<RecentActivity[]>('/dashboard/activity')
      ]);

      setStats(statsResponse.data || null);
      setRecentJobs(jobsResponse.data || []);
      setRecentActivity(activityResponse.data || []);
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Dashboard Error',
        message: 'Failed to load dashboard data'
      });
    } finally {
      setLoading(false);
    }
  };

  const loadRecentJobs = async () => {
    try {
      const response = await api.get<BatchJob[]>('/jobs/recent');
      setRecentJobs(response.data);
    } catch (error) {
      console.error('Failed to load recent jobs:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return theme.palette.success.main;
      case 'running': return theme.palette.primary.main;
      case 'failed': return theme.palette.error.main;
      case 'pending': return theme.palette.warning.main;
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

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <LinearProgress sx={{ width: '50%' }} />
      </Box>
    );
  }

  return (
    <Box>
      {/* Welcome Section */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom fontWeight="bold">
          Welcome back, {user?.full_name || user?.username}
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Monitor your PII de-identification workflows and system performance
        </Typography>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <JobsIcon color="primary" sx={{ mr: 2 }} />
                <Typography variant="h6">Total Jobs</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {stats?.total_jobs || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                +{stats?.jobs_this_week || 0} this week
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <UploadIcon color="success" sx={{ mr: 2 }} />
                <Typography variant="h6">Documents</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {stats?.total_documents || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stats?.documents_processed_today || 0} processed today
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <SecurityIcon color="warning" sx={{ mr: 2 }} />
                <Typography variant="h6">PII Found</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {stats?.pii_entities_found || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {stats?.redaction_accuracy || 0}% accuracy
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <TrendingUpIcon color="info" sx={{ mr: 2 }} />
                <Typography variant="h6">System Load</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {stats?.system_load_percentage || 0}%
              </Typography>
              <LinearProgress 
                variant="determinate" 
                value={stats?.system_load_percentage || 0}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Recent Jobs */}
        <Grid item xs={12} lg={8}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="h6" fontWeight="bold">
                Recent Jobs
              </Typography>
              <IconButton onClick={loadRecentJobs}>
                <RefreshIcon />
              </IconButton>
            </Box>

            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Job Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Progress</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {recentJobs.map((job) => (
                    <TableRow key={job.id}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {job.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" color="text.secondary">
                          {job.job_type}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {getStatusChip(job.status)}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={job.progress_percentage}
                            sx={{ width: 100 }}
                          />
                          <Typography variant="body2" color="text.secondary">
                            {job.progress_percentage}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <IconButton size="small" disabled={job.status === 'completed'}>
                          {job.status === 'running' ? <PauseIcon /> : <StartIcon />}
                        </IconButton>
                        <IconButton size="small" disabled={job.status === 'completed'}>
                          <StopIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </Grid>

        {/* Activity Feed */}
        <Grid item xs={12} lg={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" fontWeight="bold" gutterBottom>
              Recent Activity
            </Typography>

            <Box sx={{ mt: 2 }}>
              {recentActivity.map((activity, index) => (
                <Box 
                  key={activity.id} 
                  sx={{ 
                    pb: 2, 
                    mb: 2, 
                    borderBottom: index < recentActivity.length - 1 ? 1 : 0,
                    borderColor: 'divider'
                  }}
                >
                  <Typography variant="body2" fontWeight="medium">
                    {activity.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                    {activity.description}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {new Date(activity.timestamp).toLocaleString()}
                  </Typography>
                </Box>
              ))}
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Dashboard;