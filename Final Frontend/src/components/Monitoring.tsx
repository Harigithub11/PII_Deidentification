import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Activity, Server, Database, Cpu, MemoryStick, HardDrive, Network, AlertTriangle, CheckCircle, RefreshCw } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, AreaChart, Area, BarChart, Bar } from 'recharts';

const performanceData = [
  { time: '00:00', cpu: 45, memory: 62, disk: 34, network: 28 },
  { time: '01:00', cpu: 52, memory: 58, disk: 36, network: 32 },
  { time: '02:00', cpu: 38, memory: 65, disk: 38, network: 25 },
  { time: '03:00', cpu: 61, memory: 72, disk: 42, network: 45 },
  { time: '04:00', cpu: 73, memory: 68, disk: 45, network: 52 },
  { time: '05:00', cpu: 56, memory: 74, disk: 41, network: 38 },
  { time: '06:00', cpu: 48, memory: 71, disk: 39, network: 41 },
  { time: '07:00', cpu: 65, memory: 76, disk: 44, network: 48 }
];

const processingData = [
  { hour: '00', documents: 23, entities: 145, errors: 0 },
  { hour: '01', documents: 31, entities: 198, errors: 1 },
  { hour: '02', documents: 18, entities: 112, errors: 0 },
  { hour: '03', documents: 45, entities: 287, errors: 2 },
  { hour: '04', documents: 62, entities: 394, errors: 1 },
  { hour: '05', documents: 38, entities: 241, errors: 0 },
  { hour: '06', documents: 52, entities: 331, errors: 3 },
  { hour: '07', documents: 71, entities: 452, errors: 1 }
];

const systemMetrics = [
  {
    name: 'CPU Usage',
    value: 68,
    status: 'normal',
    icon: Cpu,
    color: 'from-blue-500 to-blue-600',
    threshold: 80
  },
  {
    name: 'Memory',
    value: 74,
    status: 'normal',
    icon: MemoryStick,
    color: 'from-green-500 to-green-600',
    threshold: 85
  },
  {
    name: 'Disk Usage',
    value: 42,
    status: 'normal',
    icon: HardDrive,
    color: 'from-purple-500 to-purple-600',
    threshold: 90
  },
  {
    name: 'Network I/O',
    value: 38,
    status: 'normal',
    icon: Network,
    color: 'from-orange-500 to-orange-600',
    threshold: 75
  }
];

const alerts = [
  {
    id: 'ALERT-001',
    type: 'warning',
    message: 'High memory usage detected on processing node 2',
    timestamp: '2024-01-15 14:23:45',
    resolved: false
  },
  {
    id: 'ALERT-002',
    type: 'info',
    message: 'Database backup completed successfully',
    timestamp: '2024-01-15 12:00:00',
    resolved: true
  },
  {
    id: 'ALERT-003',
    type: 'error',
    message: 'Failed to process document: corrupted file format',
    timestamp: '2024-01-15 11:45:12',
    resolved: true
  },
  {
    id: 'ALERT-004',
    type: 'success',
    message: 'System health check passed - all services operational',
    timestamp: '2024-01-15 10:00:00',
    resolved: true
  }
];

const services = [
  { name: 'API Gateway', status: 'running', uptime: '99.99%', port: '8000' },
  { name: 'Document Processor', status: 'running', uptime: '99.95%', port: '8001' },
  { name: 'PII Detection Engine', status: 'running', uptime: '99.97%', port: '8002' },
  { name: 'Database Service', status: 'running', uptime: '99.99%', port: '5432' },
  { name: 'Redis Cache', status: 'running', uptime: '99.98%', port: '6379' },
  { name: 'File Storage', status: 'warning', uptime: '98.45%', port: '9000' }
];

export function Monitoring() {
  const [realTimeData, setRealTimeData] = useState(performanceData[performanceData.length - 1]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  useEffect(() => {
    const interval = setInterval(() => {
      setRealTimeData({
        time: new Date().toLocaleTimeString(),
        cpu: Math.floor(Math.random() * 40) + 30,
        memory: Math.floor(Math.random() * 30) + 50,
        disk: Math.floor(Math.random() * 20) + 30,
        network: Math.floor(Math.random() * 30) + 20
      });
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsRefreshing(false);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'border-green-500/20 text-green-400 bg-green-500/10';
      case 'warning':
        return 'border-yellow-500/20 text-yellow-400 bg-yellow-500/10';
      case 'error':
        return 'border-red-500/20 text-red-400 bg-red-500/10';
      case 'success':
        return 'border-green-500/20 text-green-400 bg-green-500/10';
      case 'info':
        return 'border-blue-500/20 text-blue-400 bg-blue-500/10';
      default:
        return 'border-gray-500/20 text-gray-400 bg-gray-500/10';
    }
  };

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'error':
      case 'warning':
        return AlertTriangle;
      case 'success':
      case 'info':
      default:
        return CheckCircle;
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col lg:flex-row lg:items-center lg:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">System Monitoring</h1>
          <p className="text-gray-300">Real-time system performance and health monitoring</p>
        </div>
        <Button 
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="mt-4 lg:mt-0 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white"
        >
          <RefreshCw className={`h-4 w-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </motion.div>

      {/* System Metrics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6"
      >
        {systemMetrics.map((metric, index) => (
          <Card key={metric.name} className="p-6 bg-black/20 backdrop-blur-sm border-white/10 hover:bg-black/30 transition-all duration-300">
            <div className="flex items-center justify-between mb-4">
              <div className={`p-3 rounded-xl bg-gradient-to-br ${metric.color}`}>
                <metric.icon className="h-6 w-6 text-white" />
              </div>
              <Badge variant="outline" className={getStatusColor(metric.status)}>
                {metric.status}
              </Badge>
            </div>
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-gray-400 text-sm">{metric.name}</p>
                <p className="text-white font-medium">{metric.value}%</p>
              </div>
              <Progress 
                value={metric.value} 
                className={`h-2 ${metric.value > metric.threshold ? 'bg-red-500/20' : 'bg-blue-500/20'}`}
              />
              <p className="text-gray-500 text-xs mt-1">Threshold: {metric.threshold}%</p>
            </div>
          </Card>
        ))}
      </motion.div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Performance Chart */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
            <h2 className="text-xl font-semibold text-white mb-6">System Performance</h2>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={performanceData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="time" stroke="#9CA3AF" />
                  <YAxis stroke="#9CA3AF" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'rgba(0, 0, 0, 0.8)', 
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px'
                    }}
                  />
                  <Line type="monotone" dataKey="cpu" stroke="#3B82F6" strokeWidth={2} />
                  <Line type="monotone" dataKey="memory" stroke="#10B981" strokeWidth={2} />
                  <Line type="monotone" dataKey="disk" stroke="#8B5CF6" strokeWidth={2} />
                  <Line type="monotone" dataKey="network" stroke="#F59E0B" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>

        {/* Processing Activity */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
            <h2 className="text-xl font-semibold text-white mb-6">Processing Activity</h2>
            <div className="h-80">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={processingData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="hour" stroke="#9CA3AF" />
                  <YAxis stroke="#9CA3AF" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: 'rgba(0, 0, 0, 0.8)', 
                      border: '1px solid rgba(255, 255, 255, 0.1)',
                      borderRadius: '8px'
                    }}
                  />
                  <Bar dataKey="documents" fill="#3B82F6" />
                  <Bar dataKey="entities" fill="#10B981" />
                  <Bar dataKey="errors" fill="#EF4444" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        {/* Services Status */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
        >
          <Card className="bg-black/20 backdrop-blur-sm border-white/10">
            <div className="p-6 border-b border-white/10">
              <h2 className="text-xl font-semibold text-white">Services Status</h2>
            </div>
            <div className="divide-y divide-white/10">
              {services.map((service, index) => (
                <motion.div
                  key={service.name}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="p-4 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600">
                        <Server className="h-4 w-4 text-white" />
                      </div>
                      <div>
                        <p className="text-white font-medium">{service.name}</p>
                        <p className="text-gray-400 text-sm">Port: {service.port}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge variant="outline" className={getStatusColor(service.status)}>
                        {service.status}
                      </Badge>
                      <p className="text-gray-400 text-sm mt-1">{service.uptime}</p>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </Card>
        </motion.div>

        {/* Recent Alerts */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card className="bg-black/20 backdrop-blur-sm border-white/10">
            <div className="p-6 border-b border-white/10">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold text-white">Recent Alerts</h2>
                <Badge variant="outline" className="border-blue-500/20 text-blue-400 bg-blue-500/10">
                  {alerts.filter(a => !a.resolved).length} Active
                </Badge>
              </div>
            </div>
            <div className="divide-y divide-white/10 max-h-80 overflow-y-auto">
              {alerts.map((alert, index) => {
                const AlertIcon = getAlertIcon(alert.type);
                
                return (
                  <motion.div
                    key={alert.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className="p-4 hover:bg-white/5 transition-colors"
                  >
                    <div className="flex items-start gap-3">
                      <AlertIcon className={`h-5 w-5 mt-0.5 ${
                        alert.type === 'error' ? 'text-red-400' :
                        alert.type === 'warning' ? 'text-yellow-400' :
                        alert.type === 'success' ? 'text-green-400' :
                        'text-blue-400'
                      }`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-white text-sm">{alert.message}</p>
                        <div className="flex items-center gap-3 mt-1">
                          <p className="text-gray-400 text-xs">{alert.timestamp}</p>
                          <Badge 
                            variant="outline" 
                            className={alert.resolved 
                              ? 'border-green-500/20 text-green-400 bg-green-500/10' 
                              : 'border-yellow-500/20 text-yellow-400 bg-yellow-500/10'
                            }
                          >
                            {alert.resolved ? 'Resolved' : 'Active'}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}