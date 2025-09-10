import axios, { AxiosInstance, AxiosResponse, AxiosError } from 'axios';
import { ApiResponse } from '@types/index';

// Create axios instance with base configuration
const apiClient: AxiosInstance = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
apiClient.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Generic API functions
export const api = {
  get: async <T>(url: string, params?: any): Promise<ApiResponse<T>> => {
    try {
      const response = await apiClient.get<T>(url, { params });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return handleApiError(error);
    }
  },

  post: async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
    try {
      const response = await apiClient.post<T>(url, data);
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return handleApiError(error);
    }
  },

  put: async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
    try {
      const response = await apiClient.put<T>(url, data);
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return handleApiError(error);
    }
  },

  patch: async <T>(url: string, data?: any): Promise<ApiResponse<T>> => {
    try {
      const response = await apiClient.patch<T>(url, data);
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return handleApiError(error);
    }
  },

  delete: async <T>(url: string): Promise<ApiResponse<T>> => {
    try {
      const response = await apiClient.delete<T>(url);
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return handleApiError(error);
    }
  },

  upload: async <T>(url: string, formData: FormData, onUploadProgress?: (progress: number) => void): Promise<ApiResponse<T>> => {
    try {
      const response = await apiClient.post<T>(url, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total && onUploadProgress) {
            const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            onUploadProgress(progress);
          }
        },
      });
      return {
        success: true,
        data: response.data,
      };
    } catch (error) {
      return handleApiError(error);
    }
  },
};

// Error handling helper
function handleApiError(error: any): ApiResponse {
  console.error('API Error:', error);
  
  if (error.response) {
    // Server responded with error status
    const { status, data } = error.response;
    return {
      success: false,
      error: data?.detail || data?.message || `HTTP Error ${status}`,
    };
  } else if (error.request) {
    // Request made but no response received
    return {
      success: false,
      error: 'Network error - please check your connection',
    };
  } else {
    // Something else happened
    return {
      success: false,
      error: error.message || 'An unexpected error occurred',
    };
  }
}

// Specific API endpoints
export const authApi = {
  login: (credentials: { username: string; password: string }) =>
    api.post('/v1/auth/login', credentials),
  
  logout: () =>
    api.post('/v1/auth/logout'),
  
  getCurrentUser: () =>
    api.get('/v1/auth/me'),
  
  refreshToken: () =>
    api.post('/v1/auth/refresh'),

  updateProfile: (profile: any) =>
    api.put('/v1/auth/profile', profile),
};

export const jobsApi = {
  getJobs: (params?: any) =>
    api.get('/v1/batch/jobs', params),
  
  getJob: (jobId: string) =>
    api.get(`/v1/batch/jobs/${jobId}`),
  
  createJob: (jobData: any) =>
    api.post('/v1/batch/jobs', jobData),
  
  cancelJob: (jobId: string) =>
    api.post(`/v1/batch/jobs/${jobId}/cancel`),
  
  retryJob: (jobId: string) =>
    api.post(`/v1/batch/jobs/${jobId}/retry`),
  
  getJobLogs: (jobId: string) =>
    api.get(`/v1/batch/jobs/${jobId}/logs`),
};

export const workersApi = {
  getWorkers: () =>
    api.get('/v1/batch/workers'),
  
  getWorker: (workerId: string) =>
    api.get(`/v1/batch/workers/${workerId}`),
  
  restartWorker: (workerId: string) =>
    api.post(`/v1/batch/workers/${workerId}/restart`),
};

export const dashboardApi = {
  getDashboards: () =>
    api.get('/v1/dashboard'),
  
  getDashboard: (dashboardId: string) =>
    api.get(`/v1/dashboard/${dashboardId}`),
  
  getDashboardData: (dashboardId: string, forceRefresh?: boolean) =>
    api.get(`/v1/dashboard/${dashboardId}/data`, { force_refresh: forceRefresh }),
  
  getWidgetData: (dashboardId: string, widgetId: string) =>
    api.get(`/v1/dashboard/${dashboardId}/data/${widgetId}`),
  
  createDashboard: (dashboardData: any) =>
    api.post('/v1/dashboard', dashboardData),
  
  updateDashboard: (dashboardId: string, updates: any) =>
    api.put(`/v1/dashboard/${dashboardId}`, updates),
  
  deleteDashboard: (dashboardId: string) =>
    api.delete(`/v1/dashboard/${dashboardId}`),
};

export const documentsApi = {
  uploadDocument: (formData: FormData, onProgress?: (progress: number) => void) =>
    api.upload('/v1/documents/upload', formData, onProgress),
  
  getDocuments: (params?: any) =>
    api.get('/v1/documents', params),
  
  getDocument: (documentId: string) =>
    api.get(`/v1/documents/${documentId}`),
  
  processDocument: (documentId: string, options: any) =>
    api.post(`/v1/documents/${documentId}/process`, options),
  
  downloadDocument: (documentId: string) =>
    api.get(`/v1/documents/${documentId}/download`, { responseType: 'blob' }),
};

export const systemApi = {
  getHealth: () =>
    api.get('/v1/system/health'),
  
  getMetrics: () =>
    api.get('/v1/system/metrics'),
  
  getStats: () =>
    api.get('/v1/system/stats'),
};

export default apiClient;