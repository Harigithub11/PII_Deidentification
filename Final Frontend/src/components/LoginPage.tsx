import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Shield, Eye, EyeOff, User, Lock, ArrowLeft } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { api } from '../services/api';

interface LoginPageProps {
  onLogin: (username: string, password: string) => void;
  onSwitchToRegister: () => void;
}

export function LoginPage({ onLogin, onSwitchToRegister }: LoginPageProps) {
  const [username, setUsername] = useState('E-Hari');
  const [password, setPassword] = useState('Muxbx@hari1');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response = await api.login(username, password);

      if (response.success) {
        onLogin(username, password);
      } else {
        setError(response.message || 'Login failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
      console.error('Login error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen relative overflow-hidden">
      {/* Background - Mint/Teal Theme */}
      <div className="absolute inset-0 bg-gradient-to-br from-emerald-50 via-teal-50 to-cyan-50"></div>
      <div className="absolute top-0 left-0 w-[500px] h-[500px] bg-gradient-to-br from-emerald-200/40 to-transparent rounded-full blur-3xl"></div>
      <div className="absolute bottom-0 right-0 w-[400px] h-[400px] bg-gradient-to-tl from-teal-200/40 to-transparent rounded-full blur-3xl"></div>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-cyan-200/20 to-emerald-200/20 rounded-full blur-3xl"></div>

      {/* Content */}
      <div className="relative z-10 min-h-screen flex items-center justify-center p-6">
        <div className="w-full max-w-md">
          {/* Back Button */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="mb-8"
          >
            <Button
              variant="ghost"
              onClick={() => window.history.back()}
              className="text-slate-700 hover:text-slate-900 hover:bg-white/60 rounded-full gap-2 font-medium"
            >
              <ArrowLeft className="h-4 w-4" />
              Back
            </Button>
          </motion.div>

          {/* Login Form */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="bg-white/70 backdrop-blur-xl rounded-3xl border border-white/40 shadow-xl p-8"
          >
            {/* Header */}
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-teal-400 to-emerald-500 rounded-3xl mb-6 shadow-lg shadow-teal-200/50">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-slate-800 to-slate-700 bg-clip-text text-transparent mb-2">
                Welcome Back
              </h1>
              <p className="text-slate-700 font-medium">Sign in to your SecureFlow account</p>
            </div>

            {/* Error Message */}
            {error && (
              <div className="bg-red-50/80 border border-red-200/60 rounded-2xl p-4 mb-6">
                <p className="text-red-800 text-sm font-medium">{error}</p>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Username Field */}
              <div className="space-y-2">
                <label className="text-slate-800 font-semibold text-sm">Username</label>
                <div className="relative">
                  <User className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-500" />
                  <Input
                    type="text"
                    placeholder="Enter your username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="pl-12 h-12 bg-white/60 border-white/50 rounded-2xl focus:border-teal-400 focus:ring-teal-400/20 text-slate-800 placeholder-slate-500 font-medium shadow-sm"
                    required
                  />
                </div>
              </div>

              {/* Password Field */}
              <div className="space-y-2">
                <label className="text-slate-800 font-semibold text-sm">Password</label>
                <div className="relative">
                  <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-slate-500" />
                  <Input
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="pl-12 pr-12 h-12 bg-white/60 border-white/50 rounded-2xl focus:border-teal-400 focus:ring-teal-400/20 text-slate-800 placeholder-slate-500 font-medium shadow-sm"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-4 top-1/2 transform -translate-y-1/2 text-slate-500 hover:text-slate-700 transition-colors"
                  >
                    {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                  </button>
                </div>
              </div>

              {/* Demo Credentials */}
              <div className="bg-emerald-50/80 border border-emerald-200/60 rounded-2xl p-4">
                <p className="text-emerald-800 text-sm font-semibold mb-2">Demo Credentials</p>
                <p className="text-emerald-700 text-xs font-medium">Username: E-Hari</p>
                <p className="text-emerald-700 text-xs font-medium">Password: Muxbx@hari1</p>
              </div>

              {/* Forgot Password */}
              <div className="text-right">
                <button
                  type="button"
                  className="text-teal-600 hover:text-teal-700 text-sm font-semibold transition-colors"
                >
                  Forgot your password?
                </button>
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                disabled={isLoading}
                className="w-full h-12 bg-gradient-to-r from-teal-500 to-emerald-600 hover:from-teal-600 hover:to-emerald-700 text-white rounded-2xl shadow-lg shadow-teal-200/50 transition-all duration-300 font-semibold transform hover:scale-105"
              >
                {isLoading ? (
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full"
                  />
                ) : (
                  'Sign In'
                )}
              </Button>
            </form>

            {/* Register Link */}
            <div className="text-center mt-8 pt-6 border-t border-slate-200/60">
              <p className="text-slate-700 font-medium">
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={onSwitchToRegister}
                  className="text-teal-600 hover:text-teal-700 font-semibold transition-colors"
                >
                  Create one
                </button>
              </p>
            </div>
          </motion.div>

          {/* Trust Indicators */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="mt-8 text-center"
          >
            <p className="text-slate-600 text-sm mb-4 font-medium">Trusted by leading organizations worldwide</p>
            <div className="flex justify-center space-x-8 text-slate-500">
              <div className="text-center">
                <div className="font-bold text-slate-700">256-bit</div>
                <div className="text-xs font-medium">Encryption</div>
              </div>
              <div className="text-center">
                <div className="font-bold text-slate-700">SOC 2</div>
                <div className="text-xs font-medium">Type II</div>
              </div>
              <div className="text-center">
                <div className="font-bold text-slate-700">ISO 27001</div>
                <div className="text-xs font-medium">Certified</div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}