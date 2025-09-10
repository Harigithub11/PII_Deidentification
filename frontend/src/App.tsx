import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline } from '@mui/material';
import { Toaster } from 'react-hot-toast';

import { Layout } from '@components/common/Layout';
import { AuthGuard } from '@components/common/AuthGuard';
import { useUIStore } from '@store/uiStore';

// Lazy load pages for better performance
const Dashboard = React.lazy(() => import('@pages/Dashboard/Dashboard'));
const Jobs = React.lazy(() => import('@pages/Jobs/Jobs'));
const Upload = React.lazy(() => import('@pages/Upload/Upload'));
const Monitoring = React.lazy(() => import('@pages/Monitoring/Monitoring'));
const Settings = React.lazy(() => import('@pages/Settings/Settings'));
const Login = React.lazy(() => import('@pages/Login/Login'));

// Loading component for lazy-loaded routes
const PageLoader: React.FC = () => (
  <div className="loading-container">
    <div className="loading-spinner" />
  </div>
);

function App() {
  const { theme: uiTheme } = useUIStore();

  // Create Material-UI theme based on user preferences
  const theme = React.useMemo(
    () =>
      createTheme({
        palette: {
          mode: uiTheme.mode,
          primary: {
            main: uiTheme.primaryColor,
          },
          secondary: {
            main: uiTheme.secondaryColor,
          },
          background: {
            default: uiTheme.mode === 'dark' ? '#121212' : '#fafafa',
            paper: uiTheme.mode === 'dark' ? '#1e1e1e' : '#ffffff',
          },
        },
        typography: {
          fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
          h1: {
            fontWeight: 600,
          },
          h2: {
            fontWeight: 600,
          },
          h3: {
            fontWeight: 600,
          },
          h4: {
            fontWeight: 600,
          },
          h5: {
            fontWeight: 600,
          },
          h6: {
            fontWeight: 600,
          },
        },
        shape: {
          borderRadius: 12,
        },
        components: {
          // Customize Material-UI components
          MuiButton: {
            styleOverrides: {
              root: {
                textTransform: 'none',
                fontWeight: 500,
                borderRadius: 8,
              },
            },
          },
          MuiCard: {
            styleOverrides: {
              root: {
                borderRadius: 12,
                boxShadow: uiTheme.mode === 'dark' 
                  ? '0 4px 6px -1px rgba(0, 0, 0, 0.4), 0 2px 4px -1px rgba(0, 0, 0, 0.2)'
                  : '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)',
              },
            },
          },
          MuiPaper: {
            styleOverrides: {
              root: {
                borderRadius: 12,
              },
            },
          },
          MuiChip: {
            styleOverrides: {
              root: {
                borderRadius: 6,
              },
            },
          },
        },
      }),
    [uiTheme]
  );

  // Mark app as loaded after initial render
  React.useEffect(() => {
    document.body.classList.add('app-loaded');
  }, []);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <React.Suspense fallback={<PageLoader />}>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<Login />} />
            
            {/* Protected routes */}
            <Route
              path="/*"
              element={
                <AuthGuard>
                  <Layout>
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/jobs/*" element={<Jobs />} />
                      <Route path="/upload" element={<Upload />} />
                      <Route path="/monitoring" element={<Monitoring />} />
                      <Route path="/settings" element={<Settings />} />
                      <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                  </Layout>
                </AuthGuard>
              }
            />
          </Routes>
        </React.Suspense>
      </Router>
      
      {/* Global toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: theme.palette.background.paper,
            color: theme.palette.text.primary,
            borderRadius: '12px',
            boxShadow: theme.shadows[8],
          },
          success: {
            iconTheme: {
              primary: theme.palette.success.main,
              secondary: theme.palette.success.contrastText,
            },
          },
          error: {
            iconTheme: {
              primary: theme.palette.error.main,
              secondary: theme.palette.error.contrastText,
            },
          },
        }}
      />
    </ThemeProvider>
  );
}

export default App;