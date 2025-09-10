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
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Computer as WorkerIcon,
  Timeline as PerformanceIcon,
  Storage as StorageIcon,
  Memory as MemoryIcon,
  Speed as SpeedIcon,
  PlayArrow as StartIcon,
  Stop as StopIcon,
} from '@mui/icons-material';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { useUIStore } from '@store/uiStore';
import { api } from '@services/api';
import { websocketService } from '@services/websocket';
import { SystemMetrics, WorkerStatus, PerformanceData } from '@types/index';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

const Monitoring: React.FC = () => {
  const theme = useTheme();
  const { addNotification } = useUIStore();

  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null);
  const [workers, setWorkers] = useState<WorkerStatus[]>([]);
  const [performanceData, setPerformanceData] = useState<PerformanceData | null>(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('1h');

  useEffect(() => {
    loadMonitoringData();

    // Subscribe to real-time updates
    const unsubscribeMetrics = websocketService.subscribeToSystemMetrics((data) => {
      setSystemMetrics(data);
    });

    const unsubscribeWorkers = websocketService.subscribeToWorkerStatus((data) => {
      setWorkers(data);
    });

    // Refresh data every 30 seconds
    const interval = setInterval(loadMonitoringData, 30000);

    return () => {
      unsubscribeMetrics();
      unsubscribeWorkers();
      clearInterval(interval);
    };
  }, [timeRange]);

  const loadMonitoringData = async () => {
    try {
      const [metricsResponse, workersResponse, performanceResponse] = await Promise.all([
        api.get<SystemMetrics>('/monitoring/metrics'),
        api.get<WorkerStatus[]>('/monitoring/workers'),
        api.get<PerformanceData>(`/monitoring/performance?range=${timeRange}`)
      ]);

      setSystemMetrics(metricsResponse.data || null);
      setWorkers(workersResponse.data || []);
      setPerformanceData(performanceResponse.data || null);
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Monitoring Error',
        message: 'Failed to load monitoring data'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleWorkerAction = async (workerId: string, action: 'start' | 'stop' | 'restart') => {
    try {
      await api.post(`/monitoring/workers/${workerId}/${action}`);
      addNotification({
        type: 'success',
        title: 'Worker Action',
        message: `Worker ${action}ed successfully`
      });
      loadMonitoringData();
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Worker Action Failed',
        message: `Failed to ${action} worker`
      });
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return theme.palette.success.main;
      case 'running': return theme.palette.primary.main;
      case 'idle': return theme.palette.info.main;
      case 'error': return theme.palette.error.main;
      case 'offline': return theme.palette.grey[500];
      default: return theme.palette.warning.main;
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

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          callback: (value: any) => `${value}%`,
        },
      },
    },
  };

  const createChartData = (label: string, data: number[], color: string) => ({
    labels: performanceData?.timestamps || [],
    datasets: [
      {
        label,
        data,
        borderColor: color,
        backgroundColor: alpha(color, 0.1),
        fill: true,
        tension: 0.4,
      },
    ],
  });

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <LinearProgress sx={{ width: '50%' }} />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" fontWeight="bold">
          System Monitoring
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Time Range</InputLabel>
            <Select
              value={timeRange}
              onChange={(e) => setTimeRange(e.target.value)}
              label="Time Range"
            >
              <MenuItem value="1h">Last Hour</MenuItem>
              <MenuItem value="6h">Last 6 Hours</MenuItem>
              <MenuItem value="24h">Last 24 Hours</MenuItem>
              <MenuItem value="7d">Last 7 Days</MenuItem>
            </Select>
          </FormControl>
          <IconButton onClick={loadMonitoringData}>
            <RefreshIcon />
          </IconButton>
        </Box>
      </Box>

      {/* System Metrics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <MemoryIcon color="primary" sx={{ mr: 2 }} />
                <Typography variant="h6">CPU Usage</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {systemMetrics?.cpu_usage || 0}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={systemMetrics?.cpu_usage || 0}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <StorageIcon color="success" sx={{ mr: 2 }} />
                <Typography variant="h6">Memory</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {systemMetrics?.memory_usage || 0}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={systemMetrics?.memory_usage || 0}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <SpeedIcon color="warning" sx={{ mr: 2 }} />
                <Typography variant="h6">Disk I/O</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {systemMetrics?.disk_io || 0}%
              </Typography>
              <LinearProgress
                variant="determinate"
                value={systemMetrics?.disk_io || 0}
                sx={{ mt: 1 }}
              />
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <WorkerIcon color="info" sx={{ mr: 2 }} />
                <Typography variant="h6">Active Workers</Typography>
              </Box>
              <Typography variant="h3" fontWeight="bold">
                {workers.filter(w => w.status === 'running').length}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                of {workers.length} total
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Performance Charts */}
        <Grid item xs={12} lg={8}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="h6" fontWeight="bold">
                <PerformanceIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Performance Metrics
              </Typography>
            </Box>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  CPU Usage Over Time
                </Typography>
                <Box sx={{ height: 200 }}>
                  {performanceData && (
                    <Line
                      data={createChartData('CPU %', performanceData.cpu_history, theme.palette.primary.main)}
                      options={chartOptions}
                    />
                  )}
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Memory Usage Over Time
                </Typography>
                <Box sx={{ height: 200 }}>
                  {performanceData && (
                    <Line
                      data={createChartData('Memory %', performanceData.memory_history, theme.palette.success.main)}
                      options={chartOptions}
                    />
                  )}
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Job Throughput
                </Typography>
                <Box sx={{ height: 200 }}>
                  {performanceData && (
                    <Line
                      data={createChartData('Jobs/min', performanceData.throughput_history, theme.palette.warning.main)}
                      options={{ ...chartOptions, scales: { ...chartOptions.scales, y: { beginAtZero: true } } }}
                    />
                  )}
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" gutterBottom>
                  Error Rate
                </Typography>
                <Box sx={{ height: 200 }}>
                  {performanceData && (
                    <Line
                      data={createChartData('Errors %', performanceData.error_rate_history, theme.palette.error.main)}
                      options={chartOptions}
                    />
                  )}
                </Box>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {/* Workers Status */}
        <Grid item xs={12} lg={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" fontWeight="bold" gutterBottom>
              <WorkerIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Worker Status
            </Typography>

            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Worker</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Load</TableCell>
                    <TableCell align="center">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {workers.map((worker) => (
                    <TableRow key={worker.worker_id}>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {worker.worker_name}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {worker.worker_id.substring(0, 8)}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {getStatusChip(worker.status)}
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={worker.current_load}
                            sx={{ width: 60 }}
                          />
                          <Typography variant="caption">
                            {worker.current_load}%
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell align="center">
                        {worker.status === 'running' ? (
                          <IconButton
                            size="small"
                            onClick={() => handleWorkerAction(worker.worker_id, 'stop')}
                            title="Stop Worker"
                          >
                            <StopIcon fontSize="small" />
                          </IconButton>
                        ) : (
                          <IconButton
                            size="small"
                            onClick={() => handleWorkerAction(worker.worker_id, 'start')}
                            title="Start Worker"
                          >
                            <StartIcon fontSize="small" />
                          </IconButton>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            {/* System Health Summary */}
            <Box sx={{ mt: 3, p: 2, backgroundColor: alpha(theme.palette.primary.main, 0.04), borderRadius: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                System Health
              </Typography>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2">
                  Overall Status:
                </Typography>
                {getStatusChip(systemMetrics?.overall_status || 'unknown')}
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 1 }}>
                <Typography variant="body2">
                  Uptime:
                </Typography>
                <Typography variant="body2" fontWeight="medium">
                  {systemMetrics?.uptime || '0h 0m'}
                </Typography>
              </Box>
            </Box>
          </Paper>
        </Grid>

        {/* Recent Alerts */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" fontWeight="bold" gutterBottom>
              Recent System Alerts
            </Typography>

            {systemMetrics?.recent_alerts && systemMetrics.recent_alerts.length > 0 ? (
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Time</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>Component</TableCell>
                    <TableCell>Message</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {systemMetrics.recent_alerts.map((alert, index) => (
                    <TableRow key={index}>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(alert.timestamp).toLocaleString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        {getStatusChip(alert.severity)}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {alert.component}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {alert.message}
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                No recent alerts
              </Typography>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default Monitoring;