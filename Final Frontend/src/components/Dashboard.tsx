import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { TrendingUp, Shield, FileText, Users, Activity, Clock, CheckCircle, AlertTriangle, Zap } from 'lucide-react';
import { Card } from './ui/card';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { api } from '../services/api';

const stats = [
  {
    title: 'Documents Processed',
    value: '12,847',
    change: '+12.5%',
    trend: 'up',
    icon: FileText,
    color: 'from-teal-400 to-emerald-500'
  },
  {
    title: 'PII Entities Detected',
    value: '45,293',
    change: '+8.2%',
    trend: 'up',
    icon: Shield,
    color: 'from-emerald-400 to-cyan-500'
  },
  {
    title: 'Active Users',
    value: '127',
    change: '+3.1%',
    trend: 'up',
    icon: Users,
    color: 'from-cyan-400 to-teal-500'
  },
  {
    title: 'Success Rate',
    value: '99.8%',
    change: '+0.3%',
    trend: 'up',
    icon: TrendingUp,
    color: 'from-teal-400 to-emerald-500'
  }
];

const recentJobs = [
  {
    id: 'JOB-001',
    name: 'Healthcare_Records_Q4.pdf',
    status: 'completed',
    progress: 100,
    entities: 847,
    timestamp: '2 minutes ago',
    type: 'Healthcare'
  },
  {
    id: 'JOB-002',
    name: 'Financial_Data_2024.docx',
    status: 'processing',
    progress: 65,
    entities: 234,
    timestamp: '5 minutes ago',
    type: 'Financial'
  },
  {
    id: 'JOB-003',
    name: 'Customer_Database.csv',
    status: 'completed',
    progress: 100,
    entities: 1203,
    timestamp: '12 minutes ago',
    type: 'Customer Data'
  },
  {
    id: 'JOB-004',
    name: 'Legal_Documents.pdf',
    status: 'pending',
    progress: 0,
    entities: 0,
    timestamp: '15 minutes ago',
    type: 'Legal'
  }
];

const systemHealth = [
  { name: 'API Response Time', value: 98, status: 'excellent', unit: 'ms' },
  { name: 'Detection Accuracy', value: 99.8, status: 'excellent', unit: '%' },
  { name: 'System Load', value: 45, status: 'good', unit: '%' },
  { name: 'Storage Usage', value: 72, status: 'warning', unit: '%' }
];

export function Dashboard() {
  const [systemStats, setSystemStats] = useState(null)
  const [documents, setDocuments] = useState([])
  const [isLoading, setIsLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true)

        // Fetch system stats
        const statsResponse = await api.getSystemStats()
        if (statsResponse.success) {
          setSystemStats(statsResponse.data)
        }

        // Fetch recent documents
        const docsResponse = await api.getDocuments()
        if (docsResponse.success) {
          setDocuments(docsResponse.data || [])
        }
      } catch (error) {
        console.error('Failed to fetch dashboard data:', error)
      } finally {
        setIsLoading(false)
      }
    }

    fetchData()
  }, [])

  // Use real data if available, fallback to mock data
  const displayStats = systemStats ? [
    {
      title: 'Documents Processed',
      value: systemStats.documents_processed?.toString() || '0',
      change: '+12.5%',
      trend: 'up',
      icon: FileText,
      color: 'from-teal-400 to-emerald-500'
    },
    {
      title: 'PII Entities Found',
      value: systemStats.pii_entities_found?.toString() || '0',
      change: '+8.2%',
      trend: 'up',
      icon: Shield,
      color: 'from-emerald-400 to-cyan-500'
    },
    {
      title: 'Active Jobs',
      value: systemStats.active_jobs?.toString() || '0',
      change: '+3.1%',
      trend: 'up',
      icon: Users,
      color: 'from-cyan-400 to-teal-500'
    },
    {
      title: 'Compliance Score',
      value: systemStats.compliance_score ? `${systemStats.compliance_score}%` : '99.8%',
      change: '+0.3%',
      trend: 'up',
      icon: TrendingUp,
      color: 'from-teal-400 to-emerald-500'
    }
  ] : stats

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col lg:flex-row lg:items-center lg:justify-between"
      >
        <div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-slate-800 to-slate-700 bg-clip-text text-transparent mb-2">
            Dashboard
          </h1>
          <p className="text-slate-700 font-medium">Monitor your PII de-identification operations</p>
        </div>
        <div className="flex items-center gap-3 mt-4 lg:mt-0">
          <Badge className="bg-emerald-100 text-emerald-800 border-emerald-200 hover:bg-emerald-200 font-semibold">
            <div className="w-2 h-2 bg-emerald-600 rounded-full mr-2"></div>
            System Healthy
          </Badge>
          <Badge className="bg-teal-100 text-teal-800 border-teal-200 hover:bg-teal-200 font-semibold">
            <Zap className="w-3 h-3 mr-1" />
            Auto-scaling Active
          </Badge>
        </div>
      </motion.div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
        {displayStats.map((stat, index) => (
          <motion.div
            key={stat.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
          >
            <Card className="p-6 bg-white/70 backdrop-blur-sm border-white/40 hover:bg-white/90 transition-all duration-300 shadow-lg hover:shadow-xl rounded-3xl">
              <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-2xl bg-gradient-to-br ${stat.color} shadow-lg`}>
                  <stat.icon className="h-6 w-6 text-white" />
                </div>
                <Badge className="bg-emerald-100 text-emerald-800 border-emerald-200 font-semibold">
                  {stat.change}
                </Badge>
              </div>
              <div>
                <p className="text-slate-600 text-sm mb-1 font-medium">{stat.title}</p>
                <p className="text-3xl font-bold text-slate-800">{stat.value}</p>
              </div>
            </Card>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
        {/* Recent Jobs */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="xl:col-span-2"
        >
          <Card className="bg-white/70 backdrop-blur-sm border-white/40 shadow-lg rounded-3xl overflow-hidden">
            <div className="p-6 border-b border-slate-200/60">
              <div className="flex items-center justify-between">
                <h2 className="text-2xl font-bold text-slate-800">Recent Processing Jobs</h2>
                <button className="text-teal-600 hover:text-teal-700 font-semibold transition-colors">
                  View All
                </button>
              </div>
            </div>
            <div className="p-6 space-y-4">
              {recentJobs.map((job, index) => (
                <motion.div
                  key={job.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 * index }}
                  className="flex items-center justify-between p-4 bg-slate-50/80 rounded-2xl border border-slate-200/60 hover:bg-white/90 transition-all duration-200"
                >
                  <div className="flex items-center gap-4">
                    <div className="flex items-center justify-center w-12 h-12 rounded-2xl bg-gradient-to-br from-teal-400 to-emerald-500 shadow-lg">
                      <FileText className="h-6 w-6 text-white" />
                    </div>
                    <div>
                      <p className="text-slate-800 font-semibold">{job.name}</p>
                      <div className="flex items-center gap-4 mt-1">
                        <p className="text-slate-600 text-sm font-medium">{job.id}</p>
                        <Badge className="bg-teal-100 text-teal-800 border-teal-200 font-semibold">
                          {job.type}
                        </Badge>
                        <p className="text-slate-600 text-sm font-medium">{job.entities} entities</p>
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="flex items-center gap-2 mb-2">
                      {job.status === 'completed' && (
                        <CheckCircle className="h-5 w-5 text-emerald-600" />
                      )}
                      {job.status === 'processing' && (
                        <div className="w-5 h-5 border-2 border-teal-500 border-t-transparent rounded-full animate-spin" />
                      )}
                      {job.status === 'pending' && (
                        <Clock className="h-5 w-5 text-slate-500" />
                      )}
                      <Badge
                        className={
                          job.status === 'completed'
                            ? 'bg-emerald-100 text-emerald-800 border-emerald-200 font-semibold'
                            : job.status === 'processing'
                            ? 'bg-teal-100 text-teal-800 border-teal-200 font-semibold'
                            : 'bg-slate-100 text-slate-700 border-slate-200 font-semibold'
                        }
                      >
                        {job.status}
                      </Badge>
                    </div>
                    {job.status === 'processing' && (
                      <div className="w-24">
                        <Progress value={job.progress} className="h-2 bg-slate-200" />
                        <p className="text-slate-600 text-xs mt-1 font-medium">{job.progress}%</p>
                      </div>
                    )}
                    <p className="text-slate-600 text-xs mt-1 font-medium">{job.timestamp}</p>
                  </div>
                </motion.div>
              ))}
            </div>
          </Card>
        </motion.div>

        {/* System Health */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.5 }}
        >
          <Card className="bg-white/70 backdrop-blur-sm border-white/40 shadow-lg rounded-3xl">
            <div className="p-6 border-b border-slate-200/60">
              <h2 className="text-2xl font-bold text-slate-800">System Health</h2>
            </div>
            <div className="p-6 space-y-6">
              {systemHealth.map((metric, index) => (
                <motion.div
                  key={metric.name}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.1 * index }}
                  className="space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <p className="text-slate-700 font-semibold">{metric.name}</p>
                    <div className="flex items-center gap-2">
                      <p className="text-slate-800 font-bold">{metric.value}{metric.unit}</p>
                      {metric.status === 'excellent' && (
                        <div className="w-3 h-3 bg-emerald-500 rounded-full shadow-sm"></div>
                      )}
                      {metric.status === 'good' && (
                        <div className="w-3 h-3 bg-teal-500 rounded-full shadow-sm"></div>
                      )}
                      {metric.status === 'warning' && (
                        <div className="w-3 h-3 bg-orange-500 rounded-full shadow-sm"></div>
                      )}
                    </div>
                  </div>
                  <Progress 
                    value={metric.value} 
                    className={`h-3 ${
                      metric.status === 'excellent' ? 'bg-emerald-100' :
                      metric.status === 'good' ? 'bg-teal-100' :
                      'bg-orange-100'
                    }`}
                  />
                </motion.div>
              ))}
            </div>

            {/* Quick Actions */}
            <div className="p-6 border-t border-slate-200/60">
              <h3 className="text-slate-800 font-bold mb-4">Quick Actions</h3>
              <div className="space-y-3">
                <button className="w-full text-left p-4 bg-teal-50 hover:bg-teal-100 border border-teal-200 rounded-2xl text-teal-800 font-semibold transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-teal-500 rounded-xl flex items-center justify-center">
                      <FileText className="w-4 h-4 text-white" />
                    </div>
                    Upload New Document
                  </div>
                </button>
                <button className="w-full text-left p-4 bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 rounded-2xl text-emerald-800 font-semibold transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-emerald-500 rounded-xl flex items-center justify-center">
                      <Activity className="w-4 h-4 text-white" />
                    </div>
                    Create Batch Job
                  </div>
                </button>
                <button className="w-full text-left p-4 bg-cyan-50 hover:bg-cyan-100 border border-cyan-200 rounded-2xl text-cyan-800 font-semibold transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-cyan-500 rounded-xl flex items-center justify-center">
                      <Shield className="w-4 h-4 text-white" />
                    </div>
                    Compliance Report
                  </div>
                </button>
              </div>
            </div>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}