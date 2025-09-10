import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Card,
  CardContent,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  Chip,
  Grid,
  Slider,
  useTheme,
} from '@mui/material';
import {
  Save as SaveIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Security as SecurityIcon,
  Palette as ThemeIcon,
  Notifications as NotificationIcon,
  Storage as StorageIcon,
  Speed as PerformanceIcon,
  VpnKey as ApiKeyIcon,
} from '@mui/icons-material';
import { useAuthStore } from '@store/authStore';
import { useUIStore } from '@store/uiStore';
import { api } from '@services/api';
import { UserProfile, PolicyConfiguration, SystemSettings, ApiKey } from '@types/index';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div role="tabpanel" hidden={value !== index}>
    {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
  </div>
);

const Settings: React.FC = () => {
  const theme = useTheme();
  const { user, updateProfile } = useAuthStore();
  const { theme: uiTheme, setTheme, toggleThemeMode, addNotification } = useUIStore();

  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  
  // Profile settings
  const [profile, setProfile] = useState<UserProfile>({
    full_name: user?.full_name || '',
    email: user?.email || '',
    phone: user?.phone || '',
    organization: user?.organization || '',
    timezone: user?.timezone || 'UTC',
  });

  // Security settings
  const [passwordData, setPasswordData] = useState({
    current_password: '',
    new_password: '',
    confirm_password: '',
  });

  // System settings
  const [systemSettings, setSystemSettings] = useState<SystemSettings>({
    max_concurrent_jobs: 5,
    job_timeout_minutes: 60,
    auto_cleanup_days: 30,
    enable_notifications: true,
    notification_email: true,
    notification_webhook: false,
    webhook_url: '',
    storage_retention_days: 90,
    max_file_size_mb: 50,
    allowed_file_types: ['pdf', 'doc', 'docx', 'txt', 'jpg', 'png', 'tiff'],
  });

  // API Keys
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [apiKeyDialog, setApiKeyDialog] = useState(false);
  const [newApiKeyName, setNewApiKeyName] = useState('');

  // Policies
  const [policies, setPolicies] = useState<PolicyConfiguration[]>([]);
  const [policyDialog, setPolicyDialog] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyConfiguration | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      const [settingsResponse, keysResponse, policiesResponse] = await Promise.all([
        api.get<SystemSettings>('/settings/'),
        api.get<ApiKey[]>('/auth/api-keys/'),
        api.get<PolicyConfiguration[]>('/policies/')
      ]);

      setSystemSettings(settingsResponse.data);
      setApiKeys(keysResponse.data);
      setPolicies(policiesResponse.data);
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Settings Error',
        message: 'Failed to load settings'
      });
    }
  };

  const handleProfileSave = async () => {
    setLoading(true);
    try {
      await updateProfile(profile);
      addNotification({
        type: 'success',
        title: 'Profile Updated',
        message: 'Your profile has been updated successfully'
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Update Failed',
        message: 'Failed to update profile'
      });
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordChange = async () => {
    if (passwordData.new_password !== passwordData.confirm_password) {
      addNotification({
        type: 'error',
        title: 'Password Mismatch',
        message: 'New passwords do not match'
      });
      return;
    }

    setLoading(true);
    try {
      await api.post('/auth/change-password', passwordData);
      addNotification({
        type: 'success',
        title: 'Password Changed',
        message: 'Your password has been changed successfully'
      });
      setPasswordData({ current_password: '', new_password: '', confirm_password: '' });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Password Change Failed',
        message: 'Failed to change password'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSystemSettingsSave = async () => {
    setLoading(true);
    try {
      await api.put('/settings/', systemSettings);
      addNotification({
        type: 'success',
        title: 'Settings Saved',
        message: 'System settings have been updated'
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Save Failed',
        message: 'Failed to save settings'
      });
    } finally {
      setLoading(false);
    }
  };

  const handleCreateApiKey = async () => {
    if (!newApiKeyName.trim()) return;

    try {
      const response = await api.post<ApiKey>('/auth/api-keys/', { name: newApiKeyName });
      setApiKeys(prev => [...prev, response.data]);
      setApiKeyDialog(false);
      setNewApiKeyName('');
      addNotification({
        type: 'success',
        title: 'API Key Created',
        message: `API key "${newApiKeyName}" created successfully`
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Creation Failed',
        message: 'Failed to create API key'
      });
    }
  };

  const handleDeleteApiKey = async (keyId: string) => {
    try {
      await api.delete(`/auth/api-keys/${keyId}`);
      setApiKeys(prev => prev.filter(key => key.id !== keyId));
      addNotification({
        type: 'success',
        title: 'API Key Deleted',
        message: 'API key has been deleted'
      });
    } catch (error) {
      addNotification({
        type: 'error',
        title: 'Deletion Failed',
        message: 'Failed to delete API key'
      });
    }
  };

  return (
    <Box>
      <Typography variant="h4" fontWeight="bold" gutterBottom>
        Settings
      </Typography>

      <Paper sx={{ width: '100%' }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab label="Profile" />
          <Tab label="Security" />
          <Tab label="Appearance" />
          <Tab label="System" />
          <Tab label="API Keys" />
          <Tab label="Policies" />
        </Tabs>

        {/* Profile Tab */}
        <TabPanel value={activeTab} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Personal Information
                  </Typography>
                  
                  <TextField
                    fullWidth
                    label="Full Name"
                    value={profile.full_name}
                    onChange={(e) => setProfile((prev: UserProfile) => ({ ...prev, full_name: e.target.value }))}
                    margin="normal"
                  />
                  
                  <TextField
                    fullWidth
                    label="Email"
                    type="email"
                    value={profile.email}
                    onChange={(e) => setProfile((prev: UserProfile) => ({ ...prev, email: e.target.value }))}
                    margin="normal"
                  />
                  
                  <TextField
                    fullWidth
                    label="Phone"
                    value={profile.phone}
                    onChange={(e) => setProfile((prev: UserProfile) => ({ ...prev, phone: e.target.value }))}
                    margin="normal"
                  />
                  
                  <TextField
                    fullWidth
                    label="Organization"
                    value={profile.organization}
                    onChange={(e) => setProfile((prev: UserProfile) => ({ ...prev, organization: e.target.value }))}
                    margin="normal"
                  />

                  <FormControl fullWidth margin="normal">
                    <InputLabel>Timezone</InputLabel>
                    <Select
                      value={profile.timezone}
                      onChange={(e) => setProfile((prev: UserProfile) => ({ ...prev, timezone: e.target.value }))}
                      label="Timezone"
                    >
                      <MenuItem value="UTC">UTC</MenuItem>
                      <MenuItem value="America/New_York">Eastern Time</MenuItem>
                      <MenuItem value="America/Chicago">Central Time</MenuItem>
                      <MenuItem value="America/Denver">Mountain Time</MenuItem>
                      <MenuItem value="America/Los_Angeles">Pacific Time</MenuItem>
                    </Select>
                  </FormControl>

                  <Button
                    variant="contained"
                    startIcon={<SaveIcon />}
                    onClick={handleProfileSave}
                    disabled={loading}
                    sx={{ mt: 3 }}
                  >
                    Save Changes
                  </Button>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Account Status
                  </Typography>
                  
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Account Type
                    </Typography>
                    <Chip 
                      label={user?.is_superuser ? 'Administrator' : 'User'} 
                      color={user?.is_superuser ? 'primary' : 'default'}
                    />
                  </Box>
                  
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Member Since
                    </Typography>
                    <Typography variant="body1">
                      {user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                    </Typography>
                  </Box>
                  
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Last Login
                    </Typography>
                    <Typography variant="body1">
                      {user?.last_login ? new Date(user.last_login).toLocaleDateString() : 'N/A'}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Security Tab */}
        <TabPanel value={activeTab} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                    Change Password
                  </Typography>
                  
                  <TextField
                    fullWidth
                    label="Current Password"
                    type="password"
                    value={passwordData.current_password}
                    onChange={(e) => setPasswordData((prev) => ({ ...prev, current_password: e.target.value }))}
                    margin="normal"
                  />
                  
                  <TextField
                    fullWidth
                    label="New Password"
                    type="password"
                    value={passwordData.new_password}
                    onChange={(e) => setPasswordData((prev) => ({ ...prev, new_password: e.target.value }))}
                    margin="normal"
                  />
                  
                  <TextField
                    fullWidth
                    label="Confirm New Password"
                    type="password"
                    value={passwordData.confirm_password}
                    onChange={(e) => setPasswordData((prev) => ({ ...prev, confirm_password: e.target.value }))}
                    margin="normal"
                  />

                  <Button
                    variant="contained"
                    onClick={handlePasswordChange}
                    disabled={loading || !passwordData.current_password || !passwordData.new_password}
                    sx={{ mt: 3 }}
                  >
                    Change Password
                  </Button>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Security Settings
                  </Typography>
                  
                  <FormControlLabel
                    control={<Switch checked={true} />}
                    label="Two-Factor Authentication"
                    sx={{ mb: 2 }}
                  />
                  
                  <FormControlLabel
                    control={<Switch checked={true} />}
                    label="Login Notifications"
                    sx={{ mb: 2 }}
                  />
                  
                  <FormControlLabel
                    control={<Switch checked={false} />}
                    label="Session Timeout (30 min)"
                  />

                  <Alert severity="info" sx={{ mt: 3 }}>
                    Your account is protected with industry-standard security measures.
                  </Alert>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Appearance Tab */}
        <TabPanel value={activeTab} index={2}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                <ThemeIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Theme Settings
              </Typography>
              
              <FormControlLabel
                control={
                  <Switch 
                    checked={uiTheme.mode === 'dark'}
                    onChange={toggleThemeMode}
                  />
                }
                label="Dark Mode"
                sx={{ mb: 3 }}
              />

              <Typography variant="subtitle1" gutterBottom>
                Primary Color
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 3 }}>
                {['#1976d2', '#9c27b0', '#f57c00', '#388e3c', '#d32f2f'].map((color) => (
                  <Box
                    key={color}
                    sx={{
                      width: 40,
                      height: 40,
                      backgroundColor: color,
                      borderRadius: 1,
                      cursor: 'pointer',
                      border: uiTheme.primaryColor === color ? 3 : 1,
                      borderColor: uiTheme.primaryColor === color ? 'white' : 'divider',
                    }}
                    onClick={() => setTheme({ primaryColor: color })}
                  />
                ))}
              </Box>

              <Alert severity="info">
                Theme changes are automatically saved and applied across all your sessions.
              </Alert>
            </CardContent>
          </Card>
        </TabPanel>

        {/* System Tab */}
        <TabPanel value={activeTab} index={3}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    <PerformanceIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                    Processing Settings
                  </Typography>
                  
                  <Box sx={{ mb: 3 }}>
                    <Typography gutterBottom>
                      Max Concurrent Jobs: {systemSettings.max_concurrent_jobs}
                    </Typography>
                    <Slider
                      value={systemSettings.max_concurrent_jobs}
                      onChange={(_, value) => setSystemSettings(prev => ({ 
                        ...prev, 
                        max_concurrent_jobs: value as number 
                      }))}
                      min={1}
                      max={10}
                      marks
                      valueLabelDisplay="auto"
                    />
                  </Box>

                  <TextField
                    fullWidth
                    label="Job Timeout (minutes)"
                    type="number"
                    value={systemSettings.job_timeout_minutes}
                    onChange={(e) => setSystemSettings(prev => ({ 
                      ...prev, 
                      job_timeout_minutes: parseInt(e.target.value) 
                    }))}
                    margin="normal"
                  />

                  <TextField
                    fullWidth
                    label="Auto Cleanup (days)"
                    type="number"
                    value={systemSettings.auto_cleanup_days}
                    onChange={(e) => setSystemSettings(prev => ({ 
                      ...prev, 
                      auto_cleanup_days: parseInt(e.target.value) 
                    }))}
                    margin="normal"
                  />
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    <StorageIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                    Storage Settings
                  </Typography>
                  
                  <TextField
                    fullWidth
                    label="Max File Size (MB)"
                    type="number"
                    value={systemSettings.max_file_size_mb}
                    onChange={(e) => setSystemSettings(prev => ({ 
                      ...prev, 
                      max_file_size_mb: parseInt(e.target.value) 
                    }))}
                    margin="normal"
                  />

                  <TextField
                    fullWidth
                    label="Storage Retention (days)"
                    type="number"
                    value={systemSettings.storage_retention_days}
                    onChange={(e) => setSystemSettings(prev => ({ 
                      ...prev, 
                      storage_retention_days: parseInt(e.target.value) 
                    }))}
                    margin="normal"
                  />

                  <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
                    Allowed File Types
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    {systemSettings.allowed_file_types.map((type) => (
                      <Chip key={type} label={type.toUpperCase()} size="small" />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12}>
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={handleSystemSettingsSave}
                disabled={loading}
              >
                Save System Settings
              </Button>
            </Grid>
          </Grid>
        </TabPanel>

        {/* API Keys Tab */}
        <TabPanel value={activeTab} index={4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6">
                  <ApiKeyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  API Keys
                </Typography>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => setApiKeyDialog(true)}
                >
                  Create API Key
                </Button>
              </Box>

              <List>
                {apiKeys.map((key) => (
                  <ListItem key={key.id} divider>
                    <ListItemText
                      primary={key.name}
                      secondary={
                        <Box>
                          <Typography variant="caption" display="block">
                            Created: {new Date(key.created_at).toLocaleDateString()}
                          </Typography>
                          <Typography variant="caption" display="block">
                            Last used: {key.last_used ? new Date(key.last_used).toLocaleDateString() : 'Never'}
                          </Typography>
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton
                        edge="end"
                        onClick={() => handleDeleteApiKey(key.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>

              {apiKeys.length === 0 && (
                <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                  No API keys created yet
                </Typography>
              )}
            </CardContent>
          </Card>
        </TabPanel>

        {/* Policies Tab */}
        <TabPanel value={activeTab} index={5}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
                <Typography variant="h6">
                  De-identification Policies
                </Typography>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => setPolicyDialog(true)}
                >
                  Create Policy
                </Button>
              </Box>

              <List>
                {policies.map((policy) => (
                  <ListItem key={policy.id} divider>
                    <ListItemText
                      primary={policy.name}
                      secondary={
                        <Box>
                          <Typography variant="body2">
                            {policy.description}
                          </Typography>
                          <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
                            {policy.enabled_entities.slice(0, 3).map((entity) => (
                              <Chip key={entity} label={entity} size="small" />
                            ))}
                            {policy.enabled_entities.length > 3 && (
                              <Chip label={`+${policy.enabled_entities.length - 3} more`} size="small" />
                            )}
                          </Box>
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton onClick={() => {
                        setSelectedPolicy(policy);
                        setPolicyDialog(true);
                      }}>
                        <EditIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Card>
        </TabPanel>
      </Paper>

      {/* API Key Creation Dialog */}
      <Dialog open={apiKeyDialog} onClose={() => setApiKeyDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create API Key</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="API Key Name"
            fullWidth
            variant="outlined"
            value={newApiKeyName}
            onChange={(e) => setNewApiKeyName(e.target.value)}
          />
          <Alert severity="warning" sx={{ mt: 2 }}>
            API keys provide full access to your account. Store them securely and never share them.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setApiKeyDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateApiKey} variant="contained">
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Settings;