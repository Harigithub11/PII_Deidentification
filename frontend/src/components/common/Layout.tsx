import React from 'react';
import {
  Box,
  Drawer,
  AppBar,
  Toolbar,
  List,
  Typography,
  Divider,
  IconButton,
  Badge,
  Avatar,
  Menu,
  MenuItem,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Chip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Work as JobsIcon,
  CloudUpload as UploadIcon,
  MonitorHeart as MonitoringIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountIcon,
  Logout as LogoutIcon,
  Brightness4 as DarkModeIcon,
  Brightness7 as LightModeIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '@store/authStore';
import { useUIStore } from '@store/uiStore';

const drawerWidth = 240;

interface LayoutProps {
  children: React.ReactNode;
}

const navigationItems = [
  { id: 'dashboard', label: 'Dashboard', icon: DashboardIcon, path: '/' },
  { id: 'jobs', label: 'Jobs', icon: JobsIcon, path: '/jobs' },
  { id: 'upload', label: 'Upload', icon: UploadIcon, path: '/upload' },
  { id: 'monitoring', label: 'Monitoring', icon: MonitoringIcon, path: '/monitoring' },
  { id: 'settings', label: 'Settings', icon: SettingsIcon, path: '/settings' },
];

export const Layout: React.FC<LayoutProps> = ({ children }) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  
  const { user, logout } = useAuthStore();
  const { 
    sidebarOpen, 
    toggleSidebar, 
    setSidebarOpen, 
    notifications, 
    toggleThemeMode,
    theme: uiTheme 
  } = useUIStore();

  const [userMenuAnchor, setUserMenuAnchor] = React.useState<null | HTMLElement>(null);
  const [notificationsAnchor, setNotificationsAnchor] = React.useState<null | HTMLElement>(null);

  const handleUserMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setUserMenuAnchor(event.currentTarget);
  };

  const handleUserMenuClose = () => {
    setUserMenuAnchor(null);
  };

  const handleNotificationsOpen = (event: React.MouseEvent<HTMLElement>) => {
    setNotificationsAnchor(event.currentTarget);
  };

  const handleNotificationsClose = () => {
    setNotificationsAnchor(null);
  };

  const handleLogout = () => {
    logout();
    navigate('/login');
    handleUserMenuClose();
  };

  const handleNavigate = (path: string) => {
    navigate(path);
    if (window.innerWidth < theme.breakpoints.values.lg) {
      setSidebarOpen(false);
    }
  };

  const unreadNotifications = notifications.filter(n => !n.read).length;

  const drawer = (
    <Box>
      <Toolbar>
        <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 'bold' }}>
          PII System
        </Typography>
      </Toolbar>
      <Divider />
      <List>
        {navigationItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          
          return (
            <ListItem key={item.id} disablePadding>
              <ListItemButton
                selected={isActive}
                onClick={() => handleNavigate(item.path)}
                sx={{
                  mx: 1,
                  borderRadius: 2,
                  '&.Mui-selected': {
                    backgroundColor: alpha(theme.palette.primary.main, 0.12),
                    '&:hover': {
                      backgroundColor: alpha(theme.palette.primary.main, 0.16),
                    },
                  },
                }}
              >
                <ListItemIcon>
                  <Icon color={isActive ? 'primary' : 'inherit'} />
                </ListItemIcon>
                <ListItemText 
                  primary={item.label}
                  primaryTypographyProps={{
                    fontWeight: isActive ? 'medium' : 'regular',
                    color: isActive ? 'primary.main' : 'text.primary',
                  }}
                />
              </ListItemButton>
            </ListItem>
          );
        })}
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', height: '100vh' }}>
      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          width: { lg: `calc(100% - ${sidebarOpen ? drawerWidth : 0}px)` },
          ml: { lg: `${sidebarOpen ? drawerWidth : 0}px` },
          transition: theme.transitions.create(['width', 'margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={toggleSidebar}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>

          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            PII De-identification System
          </Typography>

          {/* Theme Toggle */}
          <IconButton
            color="inherit"
            onClick={toggleThemeMode}
            sx={{ mr: 1 }}
          >
            {uiTheme.mode === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
          </IconButton>

          {/* Notifications */}
          <IconButton
            color="inherit"
            onClick={handleNotificationsOpen}
            sx={{ mr: 1 }}
          >
            <Badge badgeContent={unreadNotifications} color="error">
              <NotificationsIcon />
            </Badge>
          </IconButton>

          {/* User Menu */}
          <IconButton
            size="large"
            aria-label="account of current user"
            aria-controls="menu-appbar"
            aria-haspopup="true"
            onClick={handleUserMenuOpen}
            color="inherit"
          >
            <Avatar sx={{ width: 32, height: 32 }}>
              {user?.full_name?.charAt(0) || user?.username?.charAt(0) || 'U'}
            </Avatar>
          </IconButton>
        </Toolbar>
      </AppBar>

      {/* Navigation Drawer */}
      <Box
        component="nav"
        sx={{ width: { lg: drawerWidth }, flexShrink: { lg: 0 } }}
      >
        {/* Mobile drawer */}
        <Drawer
          variant="temporary"
          open={sidebarOpen}
          onClose={toggleSidebar}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', lg: 'none' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
            },
          }}
        >
          {drawer}
        </Drawer>
        
        {/* Desktop drawer */}
        <Drawer
          variant="persistent"
          open={sidebarOpen}
          sx={{
            display: { xs: 'none', lg: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
            },
          }}
        >
          {drawer}
        </Drawer>
      </Box>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { lg: `calc(100% - ${sidebarOpen ? drawerWidth : 0}px)` },
          minHeight: '100vh',
          backgroundColor: theme.palette.background.default,
          transition: theme.transitions.create(['width'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        <Toolbar />
        {children}
      </Box>

      {/* User Menu */}
      <Menu
        anchorEl={userMenuAnchor}
        anchorOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        keepMounted
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        open={Boolean(userMenuAnchor)}
        onClose={handleUserMenuClose}
      >
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="subtitle1" fontWeight="medium">
            {user?.full_name || user?.username}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {user?.email}
          </Typography>
          {user?.is_superuser && (
            <Chip 
              label="Admin" 
              size="small" 
              color="primary" 
              sx={{ mt: 0.5 }} 
            />
          )}
        </Box>
        <Divider />
        <MenuItem onClick={() => { handleNavigate('/profile'); handleUserMenuClose(); }}>
          <ListItemIcon>
            <AccountIcon fontSize="small" />
          </ListItemIcon>
          Profile
        </MenuItem>
        <MenuItem onClick={() => { handleNavigate('/settings'); handleUserMenuClose(); }}>
          <ListItemIcon>
            <SettingsIcon fontSize="small" />
          </ListItemIcon>
          Settings
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleLogout}>
          <ListItemIcon>
            <LogoutIcon fontSize="small" />
          </ListItemIcon>
          Logout
        </MenuItem>
      </Menu>

      {/* Notifications Menu */}
      <Menu
        anchorEl={notificationsAnchor}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        open={Boolean(notificationsAnchor)}
        onClose={handleNotificationsClose}
        PaperProps={{
          sx: { width: 320, maxHeight: 400 }
        }}
      >
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="h6">
            Notifications ({unreadNotifications})
          </Typography>
        </Box>
        <Divider />
        {notifications.length === 0 ? (
          <MenuItem>
            <Typography variant="body2" color="text.secondary">
              No notifications
            </Typography>
          </MenuItem>
        ) : (
          notifications.slice(0, 5).map((notification) => (
            <MenuItem key={notification.id}>
              <Box sx={{ width: '100%' }}>
                <Typography variant="subtitle2" fontWeight={notification.read ? 'normal' : 'medium'}>
                  {notification.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {notification.message}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {new Date(notification.timestamp).toLocaleTimeString()}
                </Typography>
              </Box>
            </MenuItem>
          ))
        )}
      </Menu>
    </Box>
  );
};