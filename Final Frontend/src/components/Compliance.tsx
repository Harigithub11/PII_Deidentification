import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Shield, FileCheck, AlertTriangle, CheckCircle, Download, Calendar, Users, Eye, Lock } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Progress } from './ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';

const complianceFrameworks = [
  {
    name: 'GDPR',
    status: 'compliant',
    score: 98,
    lastAudit: '2024-01-10',
    nextAudit: '2024-04-10',
    requirements: [
      { name: 'Data Subject Rights', status: 'compliant', description: 'Right to access, portability, erasure' },
      { name: 'Consent Management', status: 'compliant', description: 'Lawful basis for processing' },
      { name: 'Breach Notification', status: 'compliant', description: '72-hour notification requirement' },
      { name: 'Data Protection Impact Assessment', status: 'warning', description: 'DPIA for high-risk processing' }
    ]
  },
  {
    name: 'HIPAA',
    status: 'compliant',
    score: 96,
    lastAudit: '2024-01-08',
    nextAudit: '2024-04-08',
    requirements: [
      { name: 'Safe Harbor Method', status: 'compliant', description: 'De-identification standards' },
      { name: 'Business Associate Agreement', status: 'compliant', description: 'BAA compliance' },
      { name: 'Privacy Rule', status: 'compliant', description: 'PHI protection standards' },
      { name: 'Security Rule', status: 'compliant', description: 'Administrative, physical, technical safeguards' }
    ]
  },
  {
    name: 'PCI-DSS',
    status: 'warning',
    score: 87,
    lastAudit: '2024-01-05',
    nextAudit: '2024-04-05',
    requirements: [
      { name: 'Card Data Protection', status: 'compliant', description: 'Secure cardholder data' },
      { name: 'Network Security', status: 'warning', description: 'Maintain secure network' },
      { name: 'Access Controls', status: 'compliant', description: 'Restrict access by business need' },
      { name: 'Regular Testing', status: 'warning', description: 'Test security systems regularly' }
    ]
  }
];

const auditLogs = [
  {
    id: 'AUDIT-001',
    type: 'GDPR Compliance Check',
    result: 'passed',
    timestamp: '2024-01-15 09:30',
    details: 'All data subject rights mechanisms verified',
    auditor: 'System Automated'
  },
  {
    id: 'AUDIT-002',
    type: 'HIPAA Security Assessment',
    result: 'passed',
    timestamp: '2024-01-15 08:15',
    details: 'De-identification processes validated',
    auditor: 'Compliance Team'
  },
  {
    id: 'AUDIT-003',
    type: 'PCI-DSS Network Scan',
    result: 'warning',
    timestamp: '2024-01-14 16:45',
    details: 'Minor configuration issues detected',
    auditor: 'Security Scanner'
  },
  {
    id: 'AUDIT-004',
    type: 'Data Retention Review',
    result: 'passed',
    timestamp: '2024-01-14 14:20',
    details: 'All retention policies properly enforced',
    auditor: 'Data Protection Officer'
  }
];

const dataProcessingActivities = [
  {
    id: 'DPA-001',
    purpose: 'Healthcare Data De-identification',
    legalBasis: 'Legitimate Interest',
    dataTypes: ['PHI', 'Medical Records', 'Patient IDs'],
    retention: '7 years',
    lastUpdated: '2024-01-10'
  },
  {
    id: 'DPA-002',
    purpose: 'Financial Data Processing',
    legalBasis: 'Contract',
    dataTypes: ['Card Numbers', 'Bank Details', 'Transaction Data'],
    retention: '5 years',
    lastUpdated: '2024-01-08'
  },
  {
    id: 'DPA-003',
    purpose: 'Customer Data Analytics',
    legalBasis: 'Consent',
    dataTypes: ['Personal Info', 'Contact Details', 'Preferences'],
    retention: '3 years',
    lastUpdated: '2024-01-05'
  }
];

export function Compliance() {
  const [selectedFramework, setSelectedFramework] = useState(0);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant':
        return 'border-green-500/20 text-green-400 bg-green-500/10';
      case 'warning':
        return 'border-yellow-500/20 text-yellow-400 bg-yellow-500/10';
      case 'non-compliant':
        return 'border-red-500/20 text-red-400 bg-red-500/10';
      default:
        return 'border-gray-500/20 text-gray-400 bg-gray-500/10';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant':
        return CheckCircle;
      case 'warning':
        return AlertTriangle;
      case 'passed':
        return CheckCircle;
      default:
        return AlertTriangle;
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold text-white mb-2">Compliance</h1>
        <p className="text-gray-300">Monitor compliance status and audit trails</p>
      </motion.div>

      {/* Compliance Overview */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-3 gap-6"
      >
        {complianceFrameworks.map((framework, index) => (
          <Card key={framework.name} className="p-6 bg-black/20 backdrop-blur-sm border-white/10 hover:bg-black/30 transition-all duration-300">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h3 className="text-white font-semibold">{framework.name}</h3>
                  <p className="text-gray-400 text-sm">Compliance Framework</p>
                </div>
              </div>
              <Badge variant="outline" className={getStatusColor(framework.status)}>
                {framework.status}
              </Badge>
            </div>
            
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-sm">Compliance Score</span>
                <span className="text-white font-medium">{framework.score}%</span>
              </div>
              <Progress value={framework.score} className="h-2" />
            </div>
            
            <div className="text-sm text-gray-400 space-y-1">
              <div className="flex justify-between">
                <span>Last Audit:</span>
                <span className="text-white">{framework.lastAudit}</span>
              </div>
              <div className="flex justify-between">
                <span>Next Audit:</span>
                <span className="text-white">{framework.nextAudit}</span>
              </div>
            </div>
          </Card>
        ))}
      </motion.div>

      {/* Detailed Compliance */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Tabs defaultValue="frameworks" className="space-y-6">
          <TabsList className="bg-black/20 backdrop-blur-sm border border-white/10">
            <TabsTrigger value="frameworks" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              Compliance Frameworks
            </TabsTrigger>
            <TabsTrigger value="audits" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              Audit Logs
            </TabsTrigger>
            <TabsTrigger value="activities" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              Data Processing
            </TabsTrigger>
          </TabsList>

          <TabsContent value="frameworks">
            <Card className="bg-black/20 backdrop-blur-sm border-white/10">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-white">Framework Requirements</h2>
                  <div className="flex gap-2">
                    {complianceFrameworks.map((framework, index) => (
                      <Button
                        key={framework.name}
                        variant={selectedFramework === index ? "default" : "outline"}
                        size="sm"
                        onClick={() => setSelectedFramework(index)}
                        className={selectedFramework === index 
                          ? "bg-gradient-to-r from-blue-500 to-purple-600 text-white" 
                          : "border-white/20 text-white hover:bg-white/10"
                        }
                      >
                        {framework.name}
                      </Button>
                    ))}
                  </div>
                </div>
              </div>
              
              <div className="p-6">
                <div className="space-y-4">
                  {complianceFrameworks[selectedFramework].requirements.map((req, index) => {
                    const StatusIcon = getStatusIcon(req.status);
                    
                    return (
                      <motion.div
                        key={req.name}
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.05 }}
                        className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10"
                      >
                        <div className="flex items-center gap-4">
                          <StatusIcon className={`h-5 w-5 ${
                            req.status === 'compliant' ? 'text-green-400' : 'text-yellow-400'
                          }`} />
                          <div>
                            <h4 className="text-white font-medium">{req.name}</h4>
                            <p className="text-gray-400 text-sm">{req.description}</p>
                          </div>
                        </div>
                        <Badge variant="outline" className={getStatusColor(req.status)}>
                          {req.status}
                        </Badge>
                      </motion.div>
                    );
                  })}
                </div>
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="audits">
            <Card className="bg-black/20 backdrop-blur-sm border-white/10">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-white">Recent Audit Activities</h2>
                  <Button variant="outline" className="border-white/20 text-white hover:bg-white/10">
                    <Download className="h-4 w-4 mr-2" />
                    Export Report
                  </Button>
                </div>
              </div>
              
              <div className="divide-y divide-white/10">
                {auditLogs.map((audit, index) => {
                  const StatusIcon = getStatusIcon(audit.result);
                  
                  return (
                    <motion.div
                      key={audit.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="p-6 hover:bg-white/5 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600">
                            <StatusIcon className="h-5 w-5 text-white" />
                          </div>
                          <div>
                            <h4 className="text-white font-medium">{audit.type}</h4>
                            <p className="text-gray-400 text-sm">{audit.details}</p>
                            <div className="flex items-center gap-4 mt-1 text-xs text-gray-500">
                              <span>{audit.id}</span>
                              <span>By {audit.auditor}</span>
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <Badge variant="outline" className={getStatusColor(audit.result)}>
                            {audit.result}
                          </Badge>
                          <p className="text-gray-400 text-sm mt-1">{audit.timestamp}</p>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            </Card>
          </TabsContent>

          <TabsContent value="activities">
            <Card className="bg-black/20 backdrop-blur-sm border-white/10">
              <div className="p-6 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold text-white">Data Processing Activities</h2>
                  <Button variant="outline" className="border-white/20 text-white hover:bg-white/10">
                    <Eye className="h-4 w-4 mr-2" />
                    View Details
                  </Button>
                </div>
              </div>
              
              <div className="divide-y divide-white/10">
                {dataProcessingActivities.map((activity, index) => (
                  <motion.div
                    key={activity.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                    className="p-6 hover:bg-white/5 transition-colors"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-4">
                        <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-green-500 to-blue-600">
                          <Lock className="h-5 w-5 text-white" />
                        </div>
                        <div>
                          <h4 className="text-white font-medium">{activity.purpose}</h4>
                          <p className="text-gray-400 text-sm">{activity.id}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="border-blue-500/20 text-blue-400 bg-blue-500/10">
                        {activity.legalBasis}
                      </Badge>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                      <div>
                        <p className="text-gray-400 mb-1">Data Types</p>
                        <div className="flex flex-wrap gap-1">
                          {activity.dataTypes.map((type, i) => (
                            <Badge key={i} variant="outline" className="border-gray-500/20 text-gray-300 bg-gray-500/10 text-xs">
                              {type}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div>
                        <p className="text-gray-400 mb-1">Retention Period</p>
                        <p className="text-white">{activity.retention}</p>
                      </div>
                      <div>
                        <p className="text-gray-400 mb-1">Last Updated</p>
                        <p className="text-white">{activity.lastUpdated}</p>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </motion.div>
    </div>
  );
}