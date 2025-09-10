import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { UIState, ThemeConfig, Notification } from '@types/index';

interface UIStore extends UIState {
  // Actions
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  setTheme: (theme: Partial<ThemeConfig>) => void;
  toggleThemeMode: () => void;
  addNotification: (notification: Omit<Notification, 'id'>) => void;
  markNotificationRead: (id: string) => void;
  removeNotification: (id: string) => void;
  clearNotifications: () => void;
  setLoading: (loading: boolean) => void;
}

const defaultTheme: ThemeConfig = {
  mode: 'light',
  primaryColor: '#1976d2',
  secondaryColor: '#dc004e',
};

export const useUIStore = create<UIStore>()(
  persist(
    (set, get) => ({
      // Initial state
      sidebarOpen: true,
      theme: defaultTheme,
      notifications: [],
      loading: false,

      // Actions
      toggleSidebar: () => {
        set((state) => ({ sidebarOpen: !state.sidebarOpen }));
      },

      setSidebarOpen: (open) => {
        set({ sidebarOpen: open });
      },

      setTheme: (themeUpdate) => {
        set((state) => ({
          theme: { ...state.theme, ...themeUpdate },
        }));
      },

      toggleThemeMode: () => {
        set((state) => ({
          theme: {
            ...state.theme,
            mode: state.theme.mode === 'light' ? 'dark' : 'light',
          },
        }));
      },

      addNotification: (notification) => {
        const id = Date.now().toString();
        const newNotification: Notification = {
          id,
          ...notification,
          timestamp: new Date().toISOString(),
          read: false,
        };

        set((state) => ({
          notifications: [newNotification, ...state.notifications].slice(0, 50), // Keep max 50 notifications
        }));

        // Auto-remove success and info notifications after 5 seconds
        if (notification.type === 'success' || notification.type === 'info') {
          setTimeout(() => {
            get().removeNotification(id);
          }, 5000);
        }
      },

      markNotificationRead: (id) => {
        set((state) => ({
          notifications: state.notifications.map((notification) =>
            notification.id === id ? { ...notification, read: true } : notification
          ),
        }));
      },

      removeNotification: (id) => {
        set((state) => ({
          notifications: state.notifications.filter((notification) => notification.id !== id),
        }));
      },

      clearNotifications: () => {
        set({ notifications: [] });
      },

      setLoading: (loading) => {
        set({ loading });
      },
    }),
    {
      name: 'ui-storage',
      partialize: (state) => ({
        sidebarOpen: state.sidebarOpen,
        theme: state.theme,
      }),
    }
  )
);