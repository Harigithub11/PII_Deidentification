import React, { useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import {
  Box,
  CardContent,
  TextField,
  Button,
  Typography,
  InputAdornment,
  IconButton,
  Alert,
  Link,
  Divider,
  Paper,
  Container,
} from '@mui/material';
import {
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  Login as LoginIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useAuthStore } from '@store/authStore';

interface LocationState {
  from: Location;
}

const Login: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isAuthenticated, isLoading } = useAuthStore();

  const [credentials, setCredentials] = useState({
    username: '',
    password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');

  // Get the page user was trying to access before login
  const from = (location.state as LocationState)?.from?.pathname || '/';

  // Redirect if already authenticated
  if (isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setCredentials(prev => ({
      ...prev,
      [name]: value,
    }));
    // Clear error when user starts typing
    if (error) setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!credentials.username || !credentials.password) {
      setError('Please enter both username and password');
      return;
    }

    const success = await login(credentials);
    if (success) {
      navigate(from, { replace: true });
    } else {
      setError('Invalid username or password');
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSubmit(e as any);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        padding: 3,
      }}
    >
      <Container maxWidth="sm">
        <Paper
          elevation={24}
          sx={{
            borderRadius: 4,
            overflow: 'hidden',
            background: 'rgba(255, 255, 255, 0.95)',
            backdropFilter: 'blur(10px)',
          }}
        >
          {/* Header */}
          <Box
            sx={{
              background: 'linear-gradient(90deg, #1976d2 0%, #1565c0 100%)',
              color: 'white',
              p: 4,
              textAlign: 'center',
            }}
          >
            <SecurityIcon sx={{ fontSize: 48, mb: 2 }} />
            <Typography variant="h4" component="h1" fontWeight="bold">
              PII De-identification
            </Typography>
            <Typography variant="subtitle1" sx={{ opacity: 0.9, mt: 1 }}>
              Professional Document Processing System
            </Typography>
          </Box>

          <CardContent sx={{ p: 4 }}>
            {/* Login Form */}
            <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
              {error && (
                <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
                  {error}
                </Alert>
              )}

              <TextField
                fullWidth
                name="username"
                label="Username"
                value={credentials.username}
                onChange={handleInputChange}
                onKeyPress={handleKeyPress}
                margin="normal"
                autoComplete="username"
                autoFocus
                disabled={isLoading}
                sx={{
                  mb: 2,
                  '& .MuiOutlinedInput-root': {
                    borderRadius: 2,
                  },
                }}
              />

              <TextField
                fullWidth
                name="password"
                label="Password"
                type={showPassword ? 'text' : 'password'}
                value={credentials.password}
                onChange={handleInputChange}
                onKeyPress={handleKeyPress}
                margin="normal"
                autoComplete="current-password"
                disabled={isLoading}
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        aria-label="toggle password visibility"
                        onClick={() => setShowPassword(!showPassword)}
                        onMouseDown={(e) => e.preventDefault()}
                        edge="end"
                        disabled={isLoading}
                      >
                        {showPassword ? <VisibilityOffIcon /> : <VisibilityIcon />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                sx={{
                  mb: 3,
                  '& .MuiOutlinedInput-root': {
                    borderRadius: 2,
                  },
                }}
              />

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={isLoading}
                startIcon={<LoginIcon />}
                sx={{
                  py: 1.5,
                  borderRadius: 2,
                  fontSize: '1.1rem',
                  fontWeight: 600,
                  background: 'linear-gradient(90deg, #1976d2 0%, #1565c0 100%)',
                  '&:hover': {
                    background: 'linear-gradient(90deg, #1565c0 0%, #0d47a1 100%)',
                  },
                }}
              >
                {isLoading ? 'Signing In...' : 'Sign In'}
              </Button>
            </Box>

            <Divider sx={{ my: 3 }} />

            {/* Demo Credentials */}
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Demo Credentials
              </Typography>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                Username: <strong>admin</strong> | Password: <strong>admin123</strong>
              </Typography>
            </Box>

            {/* Footer Links */}
            <Box sx={{ textAlign: 'center', mt: 3 }}>
              <Typography variant="body2" color="text.secondary">
                Need help? {' '}
                <Link href="mailto:support@example.com" underline="hover">
                  Contact Support
                </Link>
              </Typography>
            </Box>
          </CardContent>
        </Paper>

        {/* System Info */}
        <Box sx={{ textAlign: 'center', mt: 3 }}>
          <Typography variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.8)' }}>
            v2.1.0 | Professional PII De-identification System
          </Typography>
        </Box>
      </Container>
    </Box>
  );
};

export default Login;