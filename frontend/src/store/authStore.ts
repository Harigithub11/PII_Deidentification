import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User, AuthState } from '@types/index';
import { authApi } from '@services/api';
import { websocketService } from '@services/websocket';
import toast from 'react-hot-toast';

interface AuthStore extends AuthState {
  // Actions
  login: (credentials: { username: string; password: string }) => Promise<boolean>;
  logout: () => void;
  checkAuth: () => Promise<boolean>;
  refreshToken: () => Promise<boolean>;
  setLoading: (loading: boolean) => void;
  updateUser: (user: Partial<User>) => void;
  updateProfile: (profile: any) => Promise<void>;
}

export const useAuthStore = create<AuthStore>()(
  persist(
    (set, get) => ({
      // Initial state
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,

      // Actions
      login: async (credentials) => {
        set({ isLoading: true });
        
        try {
          const response = await authApi.login(credentials);
          
          if (response.success && response.data) {
            const { access_token, user } = response.data as any;
            
            // Store token and user
            localStorage.setItem('token', access_token);
            localStorage.setItem('user', JSON.stringify(user));
            
            // Update WebSocket authentication
            websocketService.updateAuth(access_token);
            
            set({
              token: access_token,
              user,
              isAuthenticated: true,
              isLoading: false,
            });
            
            toast.success(`Welcome back, ${user.full_name || user.username}!`);
            return true;
          } else {
            toast.error(response.error || 'Login failed');
            set({ isLoading: false });
            return false;
          }
        } catch (error) {
          console.error('Login error:', error);
          toast.error('Login failed - please try again');
          set({ isLoading: false });
          return false;
        }
      },

      logout: () => {
        // Call logout API (fire and forget)
        authApi.logout().catch(console.error);
        
        // Clear local storage
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        
        // Disconnect WebSocket
        websocketService.disconnect();
        
        // Reset state
        set({
          user: null,
          token: null,
          isAuthenticated: false,
          isLoading: false,
        });
        
        toast.success('Logged out successfully');
      },

      checkAuth: async () => {
        const token = localStorage.getItem('token');
        const userStr = localStorage.getItem('user');
        
        if (!token || !userStr) {
          return false;
        }
        
        try {
          JSON.parse(userStr); // Parse to validate
          
          // Verify token with server
          const response = await authApi.getCurrentUser();
          
          if (response.success && response.data) {
            set({
              token,
              user: response.data as User,
              isAuthenticated: true,
              isLoading: false,
            });
            
            // Update WebSocket authentication
            websocketService.updateAuth(token);
            
            return true;
          } else {
            // Token is invalid
            get().logout();
            return false;
          }
        } catch (error) {
          console.error('Auth check error:', error);
          get().logout();
          return false;
        }
      },

      refreshToken: async () => {
        try {
          const response = await authApi.refreshToken();
          
          if (response.success && response.data) {
            const { access_token } = response.data as any;
            
            localStorage.setItem('token', access_token);
            websocketService.updateAuth(access_token);
            
            set({ token: access_token });
            return true;
          } else {
            get().logout();
            return false;
          }
        } catch (error) {
          console.error('Token refresh error:', error);
          get().logout();
          return false;
        }
      },

      setLoading: (loading) => {
        set({ isLoading: loading });
      },

      updateUser: (userData) => {
        const currentUser = get().user;
        if (currentUser) {
          const updatedUser = { ...currentUser, ...userData };
          localStorage.setItem('user', JSON.stringify(updatedUser));
          set({ user: updatedUser });
        }
      },

      updateProfile: async (profile) => {
        try {
          const response = await authApi.updateProfile(profile);
          if (response.success && response.data) {
            get().updateUser(response.data);
            toast.success('Profile updated successfully');
          } else {
            throw new Error(response.error || 'Update failed');
          }
        } catch (error) {
          toast.error('Failed to update profile');
          throw error;
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        user: state.user,
        token: state.token,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);