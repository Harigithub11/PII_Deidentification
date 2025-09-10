import React, { useEffect } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';
import { useAuthStore } from '@store/authStore';

interface AuthGuardProps {
  children: React.ReactNode;
}

export const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const location = useLocation();
  const { isAuthenticated, isLoading, checkAuth, user } = useAuthStore();

  useEffect(() => {
    // Check authentication status on mount and when location changes
    if (!isAuthenticated && !isLoading) {
      checkAuth();
    }
  }, [location.pathname, isAuthenticated, isLoading, checkAuth]);

  // Show loading spinner while checking authentication
  if (isLoading) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          gap: 2,
        }}
      >
        <CircularProgress size={60} />
        <Typography variant="h6" color="text.secondary">
          Verifying authentication...
        </Typography>
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return (
      <Navigate
        to="/login"
        state={{ from: location }}
        replace
      />
    );
  }

  // Check if user account is active
  if (user && !user.is_active) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100vh',
          gap: 2,
          textAlign: 'center',
          px: 3,
        }}
      >
        <Typography variant="h4" color="error">
          Account Suspended
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Your account has been suspended. Please contact an administrator for assistance.
        </Typography>
      </Box>
    );
  }

  // User is authenticated and active, render children
  return <>{children}</>;
};