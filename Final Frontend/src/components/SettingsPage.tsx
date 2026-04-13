import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Settings, User, Shield, Bell, Database, Key, Download, Upload, Moon, Sun, Monitor } from 'lucide-react';
import { Card } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Textarea } from './ui/textarea';
import { Separator } from './ui/separator';
import { api } from '../services/api';

export function SettingsPage() {
  const [theme, setTheme] = useState('dark');
  const [notifications, setNotifications] = useState({
    email: true,
    desktop: false,
    mobile: true,
    audit: true
  });
  const [processing, setProcessing] = useState({
    defaultMethod: 'blackout',
    sensitivity: 'high',
    batchSize: '100',
    timeout: '30'
  });
  const [security, setSecurity] = useState({
    twoFactor: true,
    sessionTimeout: '60',
    apiAccess: false,
    auditLogging: true
  });
  const [profile, setProfile] = useState({
    name: 'John Doe',
    email: 'john@example.com',
    organization: 'Healthcare Corp',
    role: 'Data Protection Officer'
  });

  const handleSave = (section: string) => {
    // Simulate save operation
    alert(`${section} settings saved successfully!`);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <h1 className="text-3xl font-bold text-white mb-2">Settings</h1>
        <p className="text-gray-300">Configure your PII Shield system preferences</p>
      </motion.div>

      {/* Settings Tabs */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Tabs defaultValue="profile" className="space-y-6">
          <TabsList className="bg-black/20 backdrop-blur-sm border border-white/10">
            <TabsTrigger value="profile" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              <User className="h-4 w-4 mr-2" />
              Profile
            </TabsTrigger>
            <TabsTrigger value="security" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              <Shield className="h-4 w-4 mr-2" />
              Security
            </TabsTrigger>
            <TabsTrigger value="processing" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              <Database className="h-4 w-4 mr-2" />
              Processing
            </TabsTrigger>
            <TabsTrigger value="notifications" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              <Bell className="h-4 w-4 mr-2" />
              Notifications
            </TabsTrigger>
            <TabsTrigger value="system" className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-white/10">
              <Settings className="h-4 w-4 mr-2" />
              System
            </TabsTrigger>
          </TabsList>

          {/* Profile Settings */}
          <TabsContent value="profile">
            <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600">
                  <User className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white">Profile Settings</h2>
                  <p className="text-gray-400">Manage your personal information</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <label className="text-white text-sm">Full Name</label>
                    <Input
                      value={profile.name}
                      onChange={(e) => setProfile({...profile, name: e.target.value})}
                      className="bg-white/5 border-white/10 text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-white text-sm">Email Address</label>
                    <Input
                      type="email"
                      value={profile.email}
                      onChange={(e) => setProfile({...profile, email: e.target.value})}
                      className="bg-white/5 border-white/10 text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-white text-sm">Organization</label>
                    <Input
                      value={profile.organization}
                      onChange={(e) => setProfile({...profile, organization: e.target.value})}
                      className="bg-white/5 border-white/10 text-white"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-white text-sm">Role</label>
                    <Select value={profile.role} onValueChange={(value) => setProfile({...profile, role: value})}>
                      <SelectTrigger className="bg-white/5 border-white/10 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="admin">System Administrator</SelectItem>
                        <SelectItem value="dpo">Data Protection Officer</SelectItem>
                        <SelectItem value="analyst">Data Analyst</SelectItem>
                        <SelectItem value="user">Standard User</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Separator className="bg-white/10" />

                <div className="space-y-2">
                  <label className="text-white text-sm">Bio</label>
                  <Textarea
                    placeholder="Tell us about yourself..."
                    className="bg-white/5 border-white/10 text-white placeholder-gray-400"
                    rows={4}
                  />
                </div>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => handleSave('Profile')}
                    className="bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700"
                  >
                    Save Changes
                  </Button>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* Security Settings */}
          <TabsContent value="security">
            <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-gradient-to-br from-red-500 to-orange-600">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white">Security Settings</h2>
                  <p className="text-gray-400">Manage your account security</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">Two-Factor Authentication</p>
                      <p className="text-gray-400 text-sm">Add an extra layer of security</p>
                    </div>
                    <Switch
                      checked={security.twoFactor}
                      onCheckedChange={(checked) => setSecurity({...security, twoFactor: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">API Access</p>
                      <p className="text-gray-400 text-sm">Enable programmatic access</p>
                    </div>
                    <Switch
                      checked={security.apiAccess}
                      onCheckedChange={(checked) => setSecurity({...security, apiAccess: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">Audit Logging</p>
                      <p className="text-gray-400 text-sm">Log all user activities</p>
                    </div>
                    <Switch
                      checked={security.auditLogging}
                      onCheckedChange={(checked) => setSecurity({...security, auditLogging: checked})}
                    />
                  </div>
                </div>

                <Separator className="bg-white/10" />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <label className="text-white text-sm">Session Timeout (minutes)</label>
                    <Select value={security.sessionTimeout} onValueChange={(value) => setSecurity({...security, sessionTimeout: value})}>
                      <SelectTrigger className="bg-white/5 border-white/10 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="15">15 minutes</SelectItem>
                        <SelectItem value="30">30 minutes</SelectItem>
                        <SelectItem value="60">1 hour</SelectItem>
                        <SelectItem value="120">2 hours</SelectItem>
                        <SelectItem value="480">8 hours</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <Separator className="bg-white/10" />

                <div className="space-y-4">
                  <h3 className="text-white font-medium">API Keys</h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-4 bg-white/5 rounded-lg border border-white/10">
                      <div>
                        <p className="text-white text-sm">Production API Key</p>
                        <p className="text-gray-400 text-xs">Created: 2024-01-10</p>
                      </div>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm" className="border-white/20 text-white hover:bg-white/10">
                          <Key className="h-3 w-3 mr-1" />
                          Regenerate
                        </Button>
                      </div>
                    </div>
                  </div>
                  <Button variant="outline" className="border-white/20 text-white hover:bg-white/10">
                    <Key className="h-4 w-4 mr-2" />
                    Generate New API Key
                  </Button>
                </div>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => handleSave('Security')}
                    className="bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-600 hover:to-orange-700"
                  >
                    Save Security Settings
                  </Button>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* Processing Settings */}
          <TabsContent value="processing">
            <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-gradient-to-br from-green-500 to-blue-600">
                  <Database className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white">Processing Settings</h2>
                  <p className="text-gray-400">Configure default processing options</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <label className="text-white text-sm">Default Redaction Method</label>
                    <Select value={processing.defaultMethod} onValueChange={(value) => setProcessing({...processing, defaultMethod: value})}>
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

                  <div className="space-y-2">
                    <label className="text-white text-sm">Detection Sensitivity</label>
                    <Select value={processing.sensitivity} onValueChange={(value) => setProcessing({...processing, sensitivity: value})}>
                      <SelectTrigger className="bg-white/5 border-white/10 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="maximum">Maximum</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-white text-sm">Batch Size</label>
                    <Input
                      type="number"
                      value={processing.batchSize}
                      onChange={(e) => setProcessing({...processing, batchSize: e.target.value})}
                      className="bg-white/5 border-white/10 text-white"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-white text-sm">Processing Timeout (minutes)</label>
                    <Input
                      type="number"
                      value={processing.timeout}
                      onChange={(e) => setProcessing({...processing, timeout: e.target.value})}
                      className="bg-white/5 border-white/10 text-white"
                    />
                  </div>
                </div>

                <Separator className="bg-white/10" />

                <div className="space-y-4">
                  <h3 className="text-white font-medium">PII Entity Types</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[
                      'Social Security Numbers',
                      'Credit Card Numbers',
                      'Email Addresses',
                      'Phone Numbers',
                      'Medical Record Numbers',
                      'Driver License Numbers',
                      'Passport Numbers',
                      'Bank Account Numbers'
                    ].map((entity) => (
                      <div key={entity} className="flex items-center justify-between">
                        <span className="text-gray-300 text-sm">{entity}</span>
                        <Switch defaultChecked />
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => handleSave('Processing')}
                    className="bg-gradient-to-r from-green-500 to-blue-600 hover:from-green-600 hover:to-blue-700"
                  >
                    Save Processing Settings
                  </Button>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* Notifications Settings */}
          <TabsContent value="notifications">
            <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-gradient-to-br from-yellow-500 to-orange-600">
                  <Bell className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white">Notification Settings</h2>
                  <p className="text-gray-400">Choose how you receive updates</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">Email Notifications</p>
                      <p className="text-gray-400 text-sm">Receive updates via email</p>
                    </div>
                    <Switch
                      checked={notifications.email}
                      onCheckedChange={(checked) => setNotifications({...notifications, email: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">Desktop Notifications</p>
                      <p className="text-gray-400 text-sm">Show browser notifications</p>
                    </div>
                    <Switch
                      checked={notifications.desktop}
                      onCheckedChange={(checked) => setNotifications({...notifications, desktop: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">Mobile Push</p>
                      <p className="text-gray-400 text-sm">Send push notifications to mobile</p>
                    </div>
                    <Switch
                      checked={notifications.mobile}
                      onCheckedChange={(checked) => setNotifications({...notifications, mobile: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">Audit Alerts</p>
                      <p className="text-gray-400 text-sm">Compliance and security notifications</p>
                    </div>
                    <Switch
                      checked={notifications.audit}
                      onCheckedChange={(checked) => setNotifications({...notifications, audit: checked})}
                    />
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => handleSave('Notifications')}
                    className="bg-gradient-to-r from-yellow-500 to-orange-600 hover:from-yellow-600 hover:to-orange-700"
                  >
                    Save Notification Settings
                  </Button>
                </div>
              </div>
            </Card>
          </TabsContent>

          {/* System Settings */}
          <TabsContent value="system">
            <Card className="p-6 bg-black/20 backdrop-blur-sm border-white/10">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500 to-pink-600">
                  <Settings className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-white">System Settings</h2>
                  <p className="text-gray-400">Global system configuration</p>
                </div>
              </div>

              <div className="space-y-6">
                <div className="space-y-4">
                  <div>
                    <label className="text-white text-sm mb-3 block">Theme</label>
                    <div className="flex gap-3">
                      <Button
                        variant={theme === 'light' ? "default" : "outline"}
                        size="sm"
                        onClick={() => setTheme('light')}
                        className={theme === 'light' 
                          ? "bg-gradient-to-r from-blue-500 to-purple-600 text-white" 
                          : "border-white/20 text-white hover:bg-white/10"
                        }
                      >
                        <Sun className="h-4 w-4 mr-2" />
                        Light
                      </Button>
                      <Button
                        variant={theme === 'dark' ? "default" : "outline"}
                        size="sm"
                        onClick={() => setTheme('dark')}
                        className={theme === 'dark' 
                          ? "bg-gradient-to-r from-blue-500 to-purple-600 text-white" 
                          : "border-white/20 text-white hover:bg-white/10"
                        }
                      >
                        <Moon className="h-4 w-4 mr-2" />
                        Dark
                      </Button>
                      <Button
                        variant={theme === 'system' ? "default" : "outline"}
                        size="sm"
                        onClick={() => setTheme('system')}
                        className={theme === 'system' 
                          ? "bg-gradient-to-r from-blue-500 to-purple-600 text-white" 
                          : "border-white/20 text-white hover:bg-white/10"
                        }
                      >
                        <Monitor className="h-4 w-4 mr-2" />
                        System
                      </Button>
                    </div>
                  </div>
                </div>

                <Separator className="bg-white/10" />

                <div className="space-y-4">
                  <h3 className="text-white font-medium">Data Management</h3>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <Button variant="outline" className="border-white/20 text-white hover:bg-white/10">
                      <Download className="h-4 w-4 mr-2" />
                      Export Data
                    </Button>
                    <Button variant="outline" className="border-white/20 text-white hover:bg-white/10">
                      <Upload className="h-4 w-4 mr-2" />
                      Import Configuration
                    </Button>
                  </div>
                </div>

                <Separator className="bg-white/10" />

                <div className="space-y-4">
                  <h3 className="text-white font-medium">System Information</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Version:</span>
                        <span className="text-white">v2.1.0</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Build:</span>
                        <span className="text-white">20240115.1</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Environment:</span>
                        <span className="text-white">Production</span>
                      </div>
                    </div>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">License:</span>
                        <span className="text-white">Enterprise</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Support:</span>
                        <span className="text-white">Premium</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Expires:</span>
                        <span className="text-white">2025-01-15</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end">
                  <Button 
                    onClick={() => handleSave('System')}
                    className="bg-gradient-to-r from-purple-500 to-pink-600 hover:from-purple-600 hover:to-pink-700"
                  >
                    Save System Settings
                  </Button>
                </div>
              </div>
            </Card>
          </TabsContent>
        </Tabs>
      </motion.div>
    </div>
  );
}