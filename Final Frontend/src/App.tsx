import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, BarChart3, Upload, Briefcase, FileCheck, Activity, Settings, Menu, X, ArrowRight, FileText } from 'lucide-react';
import { Button } from './components/ui/button';
import { ThemeProvider } from './components/ThemeProvider';
import { ThemeToggle } from './components/ThemeToggle';
import { LoginPage } from './components/LoginPage';
import { RegisterPage } from './components/RegisterPage';
import { Dashboard } from './components/Dashboard';
import { FileUpload } from './components/FileUpload';
import { DocumentManager } from './components/DocumentManager';
import { JobManagement } from './components/JobManagement';
import { Compliance } from './components/Compliance';
import { Monitoring } from './components/Monitoring';
import { SettingsPage } from './components/SettingsPage';
import { PipelineVisualization } from './components/PipelineVisualization';
import { api } from './services/api';
import { authEvents } from './services/auth-events';

type Page = 'home' | 'login' | 'register' | 'dashboard' | 'upload' | 'documents' | 'jobs' | 'compliance' | 'monitoring' | 'settings';

const navigationItems = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3, component: Dashboard },
  { id: 'upload', label: 'File Upload', icon: Upload, component: FileUpload },
  { id: 'documents', label: 'Documents', icon: FileText, component: DocumentManager },
  { id: 'jobs', label: 'Job Management', icon: Briefcase, component: JobManagement },
  { id: 'compliance', label: 'Compliance', icon: FileCheck, component: Compliance },
  { id: 'monitoring', label: 'Monitoring', icon: Activity, component: Monitoring },
  { id: 'settings', label: 'Settings', icon: Settings, component: SettingsPage },
];

function AppContent() {
  const [currentPage, setCurrentPage] = useState<Page>('home');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [user, setUser] = useState({ name: 'User', email: '' });
  const [isLoading, setIsLoading] = useState(true);

  // Check for existing authentication on app load
  useEffect(() => {
    const checkAuth = async () => {
      console.log('🔍 APP: Starting auth check...');
      try {
        const isAuth = api.isAuthenticated();
        console.log('🔍 APP: api.isAuthenticated():', isAuth);

        if (isAuth) {
          console.log('🔍 APP: Token exists, calling getCurrentUser...');
          const response = await api.getCurrentUser();
          console.log('🔍 APP: getCurrentUser response:', response);

          if (response.success && response.data) {
            console.log('✅ APP: Auth check successful, user data:', response.data);
            setIsAuthenticated(true);
            setUser({
              name: response.data.full_name || response.data.username || 'User',
              email: response.data.email || ''
            });
            setCurrentPage('dashboard');
          } else {
            console.log('❌ APP: Auth check failed, clearing token. Response:', response);
            // Clear invalid token
            api.logout();
          }
        } else {
          console.log('🔍 APP: No token found, staying logged out');
        }
      } catch (error) {
        console.error('❌ APP: Auth check error:', error);
        api.logout();
      } finally {
        setIsLoading(false);
        console.log('🔍 APP: Auth check complete, loading set to false');
      }
    };

    checkAuth();

    // Listen for auth events
    const unsubscribe = authEvents.onLoginRequired(() => {
      console.log('🚨 APP: Auth event - login required, logging out user');
      setIsAuthenticated(false);
      setCurrentPage('login');
      setUser({ name: 'User', email: '' });
    });

    return unsubscribe;
  }, []);

  const handleLogin = async (username: string, password: string) => {
    console.log('🚀 LOGIN: Starting login process for user:', username);
    setIsAuthenticated(true);

    // Try to get user info
    try {
      console.log('🚀 LOGIN: Getting user info after login...');
      const userResponse = await api.getCurrentUser();
      console.log('🚀 LOGIN: User info response:', userResponse);

      if (userResponse.success && userResponse.data) {
        console.log('✅ LOGIN: User info retrieved successfully:', userResponse.data);
        setUser({
          name: userResponse.data.full_name || userResponse.data.username || username,
          email: userResponse.data.email || ''
        });
      } else {
        console.log('⚠️ LOGIN: User info failed, using fallback:', userResponse);
        setUser({ name: username, email: '' });
      }
    } catch (error) {
      console.error('❌ LOGIN: Failed to get user info:', error);
      setUser({ name: username, email: '' });
    }

    console.log('🚀 LOGIN: Navigating to dashboard...');
    setCurrentPage('dashboard');
  };

  const handleRegister = async (username: string, email: string, password: string, fullName: string) => {
    console.log('🚀 REGISTER: Starting registration process for user:', username);

    try {
      const response = await api.register({
        username,
        email,
        password,
        full_name: fullName
      });

      console.log('🚀 REGISTER: Registration API response:', response);

      if (response.success && response.data?.access_token) {
        console.log('✅ REGISTER: Registration successful, setting auth token');

        // Set the token in API client
        api.setToken(response.data.access_token);

        // Set authenticated state
        setIsAuthenticated(true);
        setUser({
          name: response.data.user?.full_name || response.data.user?.username || fullName,
          email: response.data.user?.email || email
        });

        console.log('🚀 REGISTER: Navigating to dashboard...');
        setCurrentPage('dashboard');
      } else {
        console.error('❌ REGISTER: Registration failed:', response.error || response.message);
        throw new Error(response.error || response.message || 'Registration failed');
      }
    } catch (error) {
      console.error('❌ REGISTER: Registration error:', error);
      // Error will be handled by the RegisterPage component
      throw error;
    }
  };

  const handleLogout = () => {
    api.logout();
    setIsAuthenticated(false);
    setCurrentPage('home');
    setMenuOpen(false);
    setUser({ name: 'User', email: '' });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-emerald-50 via-teal-50 to-cyan-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900">
        <div className="flex items-center gap-4">
          <div className="w-8 h-8 border-2 border-teal-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-slate-700 dark:text-gray-300 font-medium">Loading...</span>
        </div>
      </div>
    );
  }

  const renderContent = () => {
    if (!isAuthenticated) {
      if (currentPage === 'register') {
        return <RegisterPage onRegister={handleRegister} onSwitchToLogin={() => setCurrentPage('login')} />;
      }
      if (currentPage === 'login') {
        return <LoginPage onLogin={handleLogin} onSwitchToRegister={() => setCurrentPage('register')} />;
      }
      // Home page
      return (
        <div className="min-h-screen relative overflow-hidden">
          {/* Background Gradients - Mint/Teal Theme with Dark Mode Support */}
          <div className="absolute inset-0 bg-gradient-to-br from-emerald-50 via-teal-50 to-cyan-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900"></div>
          <div className="absolute top-0 left-0 w-[600px] h-[600px] bg-gradient-to-br from-emerald-200/30 dark:from-emerald-600/20 to-transparent rounded-full blur-3xl"></div>
          <div className="absolute top-20 right-0 w-[500px] h-[500px] bg-gradient-to-bl from-teal-200/40 dark:from-teal-600/20 to-transparent rounded-full blur-3xl"></div>
          <div className="absolute bottom-0 left-1/3 w-[400px] h-[400px] bg-gradient-to-tr from-cyan-200/35 dark:from-cyan-600/20 to-transparent rounded-full blur-3xl"></div>
          <div className="absolute top-1/2 right-1/4 w-[300px] h-[300px] bg-gradient-to-l from-emerald-200/25 dark:from-emerald-600/15 to-transparent rounded-full blur-3xl"></div>
          
          {/* Navigation */}
          <nav className="relative z-10 flex items-center justify-between p-6 lg:px-12">
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center gap-3"
            >
              <div className="w-12 h-12 bg-gradient-to-br from-teal-400 to-emerald-500 rounded-3xl flex items-center justify-center shadow-lg shadow-teal-200/50">
                <Shield className="w-7 h-7 text-white" />
              </div>
              <span className="text-2xl font-bold bg-gradient-to-r from-slate-700 to-slate-800 dark:from-gray-100 dark:to-gray-200 bg-clip-text text-transparent">
                SecureFlow
              </span>
            </motion.div>

            {/* Desktop Navigation */}
            <div className="hidden lg:flex items-center gap-8">
              <motion.div 
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="flex gap-8"
              >
                <button className="text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 transition-colors font-medium">Features</button>
              </motion.div>
              <motion.div 
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="flex items-center gap-4"
              >
                <Button 
                  variant="ghost" 
                  onClick={() => setCurrentPage('login')}
                  className="text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 hover:bg-white/60 dark:hover:bg-gray-800/60 rounded-full"
                >
                  Sign In
                </Button>
                <Button 
                  onClick={() => setCurrentPage('register')}
                  className="bg-gradient-to-r from-teal-500 to-emerald-600 hover:from-teal-600 hover:to-emerald-700 text-white shadow-lg shadow-teal-200/50 rounded-full px-8 py-3"
                >
                  Get Started
                </Button>
                <ThemeToggle />
              </motion.div>
            </div>

            {/* Mobile Menu Button */}
            <div className="lg:hidden flex items-center gap-2">
              <Button
                variant="ghost"
                size="icon"
                className="text-slate-700 dark:text-gray-300 hover:bg-white/60 dark:hover:bg-gray-800/60 rounded-full"
                onClick={() => setMenuOpen(!menuOpen)}
              >
                {menuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
              </Button>
            </div>
          </nav>

          {/* Mobile Menu */}
          <AnimatePresence>
            {menuOpen && (
              <motion.div
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="lg:hidden absolute top-24 left-6 right-6 bg-white/90 dark:bg-gray-800/90 backdrop-blur-xl rounded-3xl border border-white/40 dark:border-gray-700/40 shadow-xl z-50 p-6"
              >
                <div className="flex flex-col gap-4">
                  <button className="text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 text-left font-medium">Features</button>
                  <hr className="border-slate-300 dark:border-gray-600" />
                  <Button 
                    variant="ghost" 
                    onClick={() => setCurrentPage('login')}
                    className="justify-start text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 hover:bg-white/60 dark:hover:bg-gray-700/60 rounded-full"
                  >
                    Sign In
                  </Button>
                  <Button 
                    onClick={() => setCurrentPage('register')}
                    className="bg-gradient-to-r from-teal-500 to-emerald-600 text-white rounded-full"
                  >
                    Get Started
                  </Button>
                  <div className="flex justify-center pt-2">
                    <ThemeToggle />
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Hero Section */}
          <div className="relative z-10 flex flex-col lg:flex-row items-center justify-between px-6 lg:px-12 py-12 lg:py-20">
            <div className="flex-1 max-w-2xl">
              <motion.div
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
              >
                <div className="inline-flex items-center gap-2 px-5 py-3 bg-white/70 dark:bg-gray-800/70 backdrop-blur-sm rounded-full border border-teal-200/60 dark:border-teal-500/30 mb-8 shadow-sm">
                  <div className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></div>
                  <span className="text-sm text-slate-700 dark:text-gray-300 font-medium">AI-Powered Data Protection</span>
                </div>
                
                <h1 className="text-6xl lg:text-8xl font-bold mb-8 leading-tight">
                  <span className="bg-gradient-to-r from-slate-800 to-slate-700 dark:from-gray-100 dark:to-gray-200 bg-clip-text text-transparent">
                    SECURE THE
                  </span>
                  <br />
                  <span className="bg-gradient-to-r from-teal-600 via-emerald-600 to-cyan-600 dark:from-teal-400 dark:via-emerald-400 dark:to-cyan-400 bg-clip-text text-transparent">
                    FUTURE
                  </span>
                </h1>
                
                <p className="text-xl text-slate-700 dark:text-gray-300 mb-10 leading-relaxed font-medium">
                  Advanced PII de-identification powered by AI. 
                  Protect sensitive data while maintaining compliance across all industries.
                </p>
                
                <div className="flex flex-col sm:flex-row gap-4 mb-12">
                  <Button 
                    onClick={() => setCurrentPage('register')}
                    className="bg-gradient-to-r from-teal-500 to-emerald-600 hover:from-teal-600 hover:to-emerald-700 text-white rounded-full px-10 py-6 text-lg font-semibold shadow-lg shadow-teal-200/50 transform hover:scale-105 transition-all duration-200"
                  >
                    Start Redaction
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Button>
                  <Button 
                    variant="outline"
                    className="border-2 border-slate-300 dark:border-gray-600 bg-white/80 dark:bg-gray-800/80 backdrop-blur-sm hover:bg-white dark:hover:bg-gray-700 text-slate-700 dark:text-gray-300 rounded-full px-10 py-6 text-lg font-semibold hover:shadow-lg transition-all duration-200"
                  >
                    Watch Demo
                  </Button>
                </div>

                <div className="flex items-center gap-8 text-sm text-slate-600 dark:text-gray-400">
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 bg-emerald-100 dark:bg-emerald-900/50 rounded-full flex items-center justify-center">
                      <div className="w-2 h-2 bg-emerald-600 dark:bg-emerald-400 rounded-full"></div>
                    </div>
                    <span className="font-medium">99.9% Accuracy</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 bg-teal-100 dark:bg-teal-900/50 rounded-full flex items-center justify-center">
                      <div className="w-2 h-2 bg-teal-600 dark:bg-teal-400 rounded-full"></div>
                    </div>
                    <span className="font-medium">GDPR Compliant</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="w-5 h-5 bg-cyan-100 dark:bg-cyan-900/50 rounded-full flex items-center justify-center">
                      <div className="w-2 h-2 bg-cyan-600 dark:bg-cyan-400 rounded-full"></div>
                    </div>
                    <span className="font-medium">ISO 27001</span>
                  </div>
                </div>
              </motion.div>
            </div>

            {/* Digital Shield Fortress + Pipeline */}
            <motion.div 
              initial={{ opacity: 0, scale: 0.8, x: 50 }}
              animate={{ opacity: 1, scale: 1, x: 0 }}
              transition={{ delay: 0.5, duration: 0.8 }}
              className="flex-1 flex flex-col justify-center lg:justify-end mt-12 lg:mt-0 space-y-8"
            >
              {/* Main 3D Digital Shield */}
              <div className="relative flex justify-center">
                {/* Glowing background with perfect teal gradients */}
                <div className="absolute inset-0 bg-gradient-to-br from-teal-300/50 via-emerald-300/40 to-cyan-300/50 rounded-full blur-3xl scale-150"></div>
                <div className="absolute inset-0 bg-gradient-to-tl from-emerald-200/40 via-teal-200/30 to-cyan-200/40 rounded-full blur-2xl scale-125"></div>
                
                {/* Hexagonal floating elements */}
                <motion.div
                  animate={{ y: [-25, 25, -25], rotate: [0, 10, 0] }}
                  transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
                  className="absolute top-8 -left-20 w-28 h-28 bg-gradient-to-br from-teal-400 to-emerald-500 rounded-3xl flex items-center justify-center shadow-2xl shadow-teal-300/60"
                  style={{ clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)' }}
                >
                  <Shield className="w-14 h-14 text-white" />
                </motion.div>
                
                <motion.div
                  animate={{ y: [25, -25, 25], rotate: [0, -8, 0] }}
                  transition={{ duration: 6, repeat: Infinity, ease: "easeInOut", delay: 2 }}
                  className="absolute bottom-8 -right-20 w-24 h-24 bg-gradient-to-br from-emerald-400 to-cyan-500 rounded-2xl flex items-center justify-center shadow-2xl shadow-emerald-300/60"
                  style={{ clipPath: 'polygon(25% 0%, 75% 0%, 100% 50%, 75% 100%, 25% 100%, 0% 50%)' }}
                >
                  <FileCheck className="w-12 h-12 text-white" />
                </motion.div>

                <motion.div
                  animate={{ y: [-20, 20, -20], x: [-8, 8, -8], rotate: [0, 6, 0] }}
                  transition={{ duration: 10, repeat: Infinity, ease: "easeInOut", delay: 4 }}
                  className="absolute top-1/4 -right-24 w-20 h-20 bg-gradient-to-br from-cyan-400 to-teal-500 rounded-xl flex items-center justify-center shadow-xl shadow-cyan-300/60"
                >
                  <Activity className="w-10 h-10 text-white" />
                </motion.div>

                {/* Data protection particles */}
                <motion.div
                  animate={{ 
                    scale: [1, 1.3, 1], 
                    opacity: [0.5, 1, 0.5],
                    rotate: [0, 180, 360] 
                  }}
                  transition={{ duration: 12, repeat: Infinity, ease: "easeInOut", delay: 1 }}
                  className="absolute top-1/6 left-1/5 w-10 h-10 bg-gradient-to-br from-teal-300 to-emerald-400 rounded-full shadow-lg"
                />
                
                <motion.div
                  animate={{ 
                    scale: [1, 1.2, 1], 
                    opacity: [0.4, 0.9, 0.4],
                    rotate: [360, 180, 0] 
                  }}
                  transition={{ duration: 8, repeat: Infinity, ease: "easeInOut", delay: 6 }}
                  className="absolute bottom-1/4 left-1/4 w-8 h-8 bg-gradient-to-br from-emerald-300 to-cyan-400 rounded-full shadow-lg"
                />

                <motion.div
                  animate={{ 
                    scale: [1, 1.4, 1], 
                    opacity: [0.3, 0.8, 0.3],
                    rotate: [0, 270, 0] 
                  }}
                  transition={{ duration: 15, repeat: Infinity, ease: "easeInOut", delay: 3 }}
                  className="absolute top-1/2 right-1/6 w-6 h-6 bg-gradient-to-br from-cyan-300 to-teal-400 rounded-full shadow-lg"
                />
              </div>

              {/* Interactive Pipeline Visualization */}
              <motion.div
                initial={{ opacity: 0, y: 30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1.2, duration: 0.8 }}
                className="relative"
              >
                <PipelineVisualization />
              </motion.div>
            </motion.div>
          </div>

          {/* Stats Section */}
          <motion.div 
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8 }}
            className="relative z-10 px-6 lg:px-12 pb-24"
          >
            <div className="bg-white/60 dark:bg-gray-800/60 backdrop-blur-xl rounded-3xl border border-white/40 dark:border-gray-700/40 shadow-xl p-8 lg:p-12">
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                <div className="text-center">
                  <div className="text-5xl font-bold bg-gradient-to-r from-teal-600 to-emerald-600 dark:from-teal-400 dark:to-emerald-400 bg-clip-text text-transparent mb-2">
                    10M+
                  </div>
                  <div className="text-slate-700 dark:text-gray-300 font-medium">Documents Processed</div>
                </div>
                <div className="text-center">
                  <div className="text-5xl font-bold bg-gradient-to-r from-emerald-600 to-cyan-600 dark:from-emerald-400 dark:to-cyan-400 bg-clip-text text-transparent mb-2">
                    99.9%
                  </div>
                  <div className="text-slate-700 dark:text-gray-300 font-medium">Detection Accuracy</div>
                </div>
                <div className="text-center">
                  <div className="text-5xl font-bold bg-gradient-to-r from-cyan-600 to-teal-600 dark:from-cyan-400 dark:to-teal-400 bg-clip-text text-transparent mb-2">
                    500+
                  </div>
                  <div className="text-slate-700 dark:text-gray-300 font-medium">Enterprise Clients</div>
                </div>
                <div className="text-center">
                  <div className="text-5xl font-bold bg-gradient-to-r from-teal-600 to-emerald-600 dark:from-teal-400 dark:to-emerald-400 bg-clip-text text-transparent mb-2">
                    24/7
                  </div>
                  <div className="text-slate-700 dark:text-gray-300 font-medium">Global Support</div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      );
    }

    const currentItem = navigationItems.find(item => item.id === currentPage);
    const Component = currentItem?.component || Dashboard;

    // Special handling for FileUpload to pass navigation callback
    if (currentPage === 'upload') {
      return <FileUpload onNavigateToDocuments={() => setCurrentPage('documents')} />;
    }

    return <Component />;
  };

  // Authenticated App Layout
  if (isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-emerald-50 via-teal-50 to-cyan-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 relative">
        {/* Background Elements */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-bl from-teal-200/30 dark:from-teal-600/20 to-transparent rounded-full blur-3xl"></div>
        <div className="absolute bottom-0 left-0 w-96 h-96 bg-gradient-to-tr from-emerald-200/30 dark:from-emerald-600/20 to-transparent rounded-full blur-3xl"></div>

        {/* Top Navigation */}
        <nav className="relative z-50 bg-white/70 dark:bg-gray-800/70 backdrop-blur-xl border-b border-white/30 dark:border-gray-700/30">
          <div className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-6">
                <div className="flex items-center gap-3">
                  <div className="w-11 h-11 bg-gradient-to-br from-teal-400 to-emerald-500 rounded-2xl flex items-center justify-center shadow-lg shadow-teal-200/50">
                    <Shield className="w-6 h-6 text-white" />
                  </div>
                  <span className="text-xl font-bold bg-gradient-to-r from-slate-700 to-slate-800 dark:from-gray-100 dark:to-gray-200 bg-clip-text text-transparent">
                    SecureFlow
                  </span>
                </div>
                
                {/* Desktop Navigation */}
                <div className="hidden lg:flex items-center gap-1">
                  {navigationItems.map((item) => (
                    <Button
                      key={item.id}
                      variant="ghost"
                      onClick={() => setCurrentPage(item.id as Page)}
                      className={`gap-2 rounded-full px-5 py-3 font-medium ${
                        currentPage === item.id 
                          ? 'bg-gradient-to-r from-teal-500 to-emerald-600 text-white shadow-lg shadow-teal-200/50' 
                          : 'text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 hover:bg-white/60 dark:hover:bg-gray-700/60'
                      }`}
                    >
                      <item.icon className="h-4 w-4" />
                      {item.label}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-4">
                <ThemeToggle />
                <div className="hidden lg:flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-sm font-semibold text-slate-800 dark:text-gray-200">{user.name}</div>
                    <div className="text-xs text-slate-600 dark:text-gray-400">{user.email}</div>
                  </div>
                  <div className="w-10 h-10 bg-gradient-to-br from-teal-400 to-emerald-500 rounded-full flex items-center justify-center shadow-lg shadow-teal-200/50">
                    <span className="text-white font-semibold">{user.name.charAt(0)}</span>
                  </div>
                </div>
                
                <Button
                  variant="ghost"
                  onClick={handleLogout}
                  className="text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 hover:bg-white/60 dark:hover:bg-gray-700/60 rounded-full font-medium"
                >
                  Sign Out
                </Button>

                {/* Mobile Menu Button */}
                <Button
                  variant="ghost"
                  size="icon"
                  className="lg:hidden text-slate-700 dark:text-gray-300 hover:bg-white/60 dark:hover:bg-gray-700/60 rounded-full"
                  onClick={() => setMenuOpen(!menuOpen)}
                >
                  {menuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
                </Button>
              </div>
            </div>
          </div>

          {/* Mobile Menu */}
          <AnimatePresence>
            {menuOpen && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="lg:hidden border-t border-white/30 dark:border-gray-700/30 bg-white/80 dark:bg-gray-800/80 backdrop-blur-xl"
              >
                <div className="px-6 py-4 space-y-2">
                  {navigationItems.map((item) => (
                    <Button
                      key={item.id}
                      variant="ghost"
                      onClick={() => {
                        setCurrentPage(item.id as Page);
                        setMenuOpen(false);
                      }}
                      className={`w-full justify-start gap-3 rounded-2xl font-medium ${
                        currentPage === item.id 
                          ? 'bg-gradient-to-r from-teal-500 to-emerald-600 text-white' 
                          : 'text-slate-700 dark:text-gray-300 hover:text-slate-900 dark:hover:text-gray-100 hover:bg-white/60 dark:hover:bg-gray-700/60'
                      }`}
                    >
                      <item.icon className="h-4 w-4" />
                      {item.label}
                    </Button>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </nav>

        {/* Main Content */}
        <main className="relative z-10">
          <AnimatePresence mode="wait">
            <motion.div
              key={currentPage}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
              className="p-6 lg:p-12"
            >
              {renderContent()}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    );
  }

  return renderContent();
}

export default function App() {
  return (
    <ThemeProvider>
      <AppContent />
    </ThemeProvider>
  );
}