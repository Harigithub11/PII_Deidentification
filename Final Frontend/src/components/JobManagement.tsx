import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Plus, Search, Filter, MoreVertical, Play, Pause, Square, Download, Eye, Clock, CheckCircle, XCircle, AlertCircle } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from './ui/dropdown-menu';
import { api } from '../services/api';

interface Job {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'paused';
  priority: 'low' | 'medium' | 'high';
  progress: number;
  filesCount: number;
  entitiesDetected: number;
  createdAt: string;
  estimatedTime: string;
  type: 'single' | 'batch';
}

const jobsData: Job[] = [
  {
    id: 'JOB-001',
    name: 'Healthcare Records Q4 2024',
    status: 'completed',
    priority: 'high',
    progress: 100,
    filesCount: 247,
    entitiesDetected: 15847,
    createdAt: '2024-01-15 14:30',
    estimatedTime: '0 min',
    type: 'batch'
  },
  {
    id: 'JOB-002',
    name: 'Financial Data Processing',
    status: 'running',
    priority: 'high',
    progress: 67,
    filesCount: 89,
    entitiesDetected: 5203,
    createdAt: '2024-01-15 15:45',
    estimatedTime: '12 min',
    type: 'batch'
  },
  {
    id: 'JOB-003',
    name: 'Legal Document Review',
    status: 'pending',
    priority: 'medium',
    progress: 0,
    filesCount: 156,
    entitiesDetected: 0,
    createdAt: '2024-01-15 16:20',
    estimatedTime: '45 min',
    type: 'batch'
  },
  {
    id: 'JOB-004',
    name: 'Customer Database Cleanup',
    status: 'paused',
    priority: 'low',
    progress: 23,
    filesCount: 1,
    entitiesDetected: 892,
    createdAt: '2024-01-15 13:15',
    estimatedTime: '28 min',
    type: 'single'
  },
  {
    id: 'JOB-005',
    name: 'Insurance Claims Data',
    status: 'failed',
    priority: 'medium',
    progress: 45,
    filesCount: 67,
    entitiesDetected: 2104,
    createdAt: '2024-01-15 12:00',
    estimatedTime: 'Failed',
    type: 'batch'
  }
];

export function JobManagement() {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [jobs, setJobs] = useState(jobsData);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchJobs = async () => {
      try {
        setIsLoading(true);
        const response = await api.getBatchJobs();

        if (response.success && response.data) {
          // Map backend data to frontend format
          const mappedJobs = response.data.map(job => ({
            id: job.id,
            name: job.name,
            status: job.status === 'queued' ? 'pending' : job.status as any,
            priority: job.priority,
            progress: job.progress,
            filesCount: job.files_count,
            entitiesDetected: job.pii_found,
            createdAt: new Date(job.created_at).toLocaleDateString(),
            estimatedTime: job.completed_at ? 'Completed' : 'Processing...',
            type: 'batch' as const
          }));
          setJobs(mappedJobs);
        }
      } catch (error) {
        console.error('Failed to fetch jobs:', error);
        // Keep using static data on error
      } finally {
        setIsLoading(false);
      }
    };

    fetchJobs();
  }, []);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return CheckCircle;
      case 'running':
        return Play;
      case 'failed':
        return XCircle;
      case 'paused':
        return Pause;
      case 'pending':
        return Clock;
      default:
        return AlertCircle;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'border-green-500/20 text-green-400 bg-green-500/10';
      case 'running':
        return 'border-blue-500/20 text-blue-400 bg-blue-500/10';
      case 'failed':
        return 'border-red-500/20 text-red-400 bg-red-500/10';
      case 'paused':
        return 'border-orange-500/20 text-orange-400 bg-orange-500/10';
      case 'pending':
        return 'border-gray-500/20 text-gray-400 bg-gray-500/10';
      default:
        return 'border-gray-500/20 text-gray-400 bg-gray-500/10';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'high':
        return 'border-red-500/20 text-red-400 bg-red-500/10';
      case 'medium':
        return 'border-yellow-500/20 text-yellow-400 bg-yellow-500/10';
      case 'low':
        return 'border-green-500/20 text-green-400 bg-green-500/10';
      default:
        return 'border-gray-500/20 text-gray-400 bg-gray-500/10';
    }
  };

  const filteredJobs = jobs.filter(job => {
    const matchesSearch = job.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         job.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = statusFilter === 'all' || job.status === statusFilter;
    const matchesPriority = priorityFilter === 'all' || job.priority === priorityFilter;
    
    return matchesSearch && matchesStatus && matchesPriority;
  });

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col lg:flex-row lg:items-center lg:justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Job Management</h1>
          <p className="text-gray-300">Monitor and control your de-identification jobs</p>
        </div>
        <Button className="mt-4 lg:mt-0 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white">
          <Plus className="h-4 w-4 mr-2" />
          Create New Job
        </Button>
      </motion.div>

      {/* Stats */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
      >
        {[
          { label: 'Total Jobs', value: '127', color: 'from-blue-500 to-blue-600' },
          { label: 'Running', value: '8', color: 'from-green-500 to-green-600' },
          { label: 'Completed', value: '104', color: 'from-purple-500 to-purple-600' },
          { label: 'Failed', value: '3', color: 'from-red-500 to-red-600' }
        ].map((stat, index) => (
          <Card key={stat.label} className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">{stat.label}</p>
                <p className="text-2xl font-bold text-white">{stat.value}</p>
              </div>
              <div className={`p-3 rounded-xl bg-gradient-to-br ${stat.color}`}>
                <div className="w-6 h-6"></div>
              </div>
            </div>
          </Card>
        ))}
      </motion.div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="flex-1">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                <Input
                  placeholder="Search jobs by name or ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10 bg-white/5 border-white/10 text-white placeholder-gray-400"
                />
              </div>
            </div>
            <div className="flex gap-4">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-40 bg-white/5 border-white/10 text-white">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="running">Running</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                  <SelectItem value="paused">Paused</SelectItem>
                </SelectContent>
              </Select>
              
              <Select value={priorityFilter} onValueChange={setPriorityFilter}>
                <SelectTrigger className="w-40 bg-white/5 border-white/10 text-white">
                  <SelectValue placeholder="Priority" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Priority</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </Card>
      </motion.div>

      {/* Jobs List */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="bg-black/20 backdrop-blur-sm border-white/10 overflow-hidden">
          <div className="p-6 border-b border-white/10">
            <h2 className="text-xl font-semibold text-white">
              Jobs ({filteredJobs.length})
            </h2>
          </div>
          
          <div className="divide-y divide-white/10">
            {filteredJobs.map((job, index) => {
              const StatusIcon = getStatusIcon(job.status);
              
              return (
                <motion.div
                  key={job.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="p-6 hover:bg-white/5 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4 flex-1">
                      <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600">
                        <StatusIcon className="h-6 w-6 text-white" />
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3 mb-2">
                          <h3 className="text-white font-medium truncate">{job.name}</h3>
                          <Badge variant="outline" className={getPriorityColor(job.priority)}>
                            {job.priority}
                          </Badge>
                          <Badge variant="outline" className="border-blue-500/20 text-blue-400 bg-blue-500/10">
                            {job.type}
                          </Badge>
                        </div>
                        
                        <div className="flex items-center gap-6 text-sm text-gray-400">
                          <span>{job.id}</span>
                          <span>{job.filesCount} files</span>
                          <span>{job.entitiesDetected.toLocaleString()} entities</span>
                          <span>{job.createdAt}</span>
                        </div>
                        
                        {job.status === 'running' && (
                          <div className="mt-3">
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs text-gray-400">Progress</span>
                              <span className="text-xs text-gray-400">{job.progress}%</span>
                            </div>
                            <Progress value={job.progress} className="h-2" />
                          </div>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className={getStatusColor(job.status)}>
                        {job.status}
                      </Badge>
                      
                      <div className="text-right text-sm">
                        <p className="text-gray-400">ETA</p>
                        <p className="text-white">{job.estimatedTime}</p>
                      </div>
                      
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" className="text-gray-400 hover:text-white">
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="bg-black/90 backdrop-blur-sm border-white/10">
                          <DropdownMenuItem className="text-white hover:bg-white/10">
                            <Eye className="h-4 w-4 mr-2" />
                            View Details
                          </DropdownMenuItem>
                          {job.status === 'running' && (
                            <DropdownMenuItem className="text-white hover:bg-white/10">
                              <Pause className="h-4 w-4 mr-2" />
                              Pause Job
                            </DropdownMenuItem>
                          )}
                          {job.status === 'paused' && (
                            <DropdownMenuItem className="text-white hover:bg-white/10">
                              <Play className="h-4 w-4 mr-2" />
                              Resume Job
                            </DropdownMenuItem>
                          )}
                          {job.status === 'completed' && (
                            <DropdownMenuItem className="text-white hover:bg-white/10">
                              <Download className="h-4 w-4 mr-2" />
                              Download Results
                            </DropdownMenuItem>
                          )}
                          {job.status !== 'completed' && (
                            <DropdownMenuItem className="text-red-400 hover:bg-red-500/10">
                              <Square className="h-4 w-4 mr-2" />
                              Cancel Job
                            </DropdownMenuItem>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
          
          {filteredJobs.length === 0 && (
            <div className="p-12 text-center">
              <p className="text-gray-400">No jobs found matching your criteria.</p>
            </div>
          )}
        </Card>
      </motion.div>
    </div>
  );
}