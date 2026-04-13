import { authEvents } from './auth-events'

interface ApiResponse<T = any> {
  success: boolean
  message: string
  data?: T
  error?: string
}

interface AuthTokens {
  access_token: string
  token_type: string
  user?: {
    id: string
    username: string
    email?: string
    full_name?: string
  }
}

interface SystemStats {
  documents_processed: number
  active_jobs: number
  compliance_score: number
  pii_entities_found: number
  system_status: {
    cpu_usage: number
    memory_usage: number
    storage_usage: number
    services_status: string
  }
}

interface Document {
  id: string
  filename: string
  upload_date: string
  file_size: number
  file_type: string
  status: "processing" | "completed" | "failed"
  pii_entities_found?: number
}

interface BatchJob {
  id: string
  name: string
  status: "queued" | "processing" | "completed" | "failed"
  progress: number
  files_count: number
  pii_found: number
  created_at: string
  completed_at?: string
  priority: "low" | "medium" | "high"
}

class ApiClient {
  private baseURL: string
  private token: string | null = null

  constructor() {
    this.baseURL = import.meta.env.VITE_API_URL || "http://localhost:8002"

    // Load token from localStorage if available
    if (typeof window !== "undefined") {
      this.token = localStorage.getItem("auth_token")

      // Listen for localStorage changes (cross-tab sync)
      window.addEventListener('storage', (e) => {
        if (e.key === 'auth_token') {
          this.token = e.newValue
        }
      })
    }
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseURL}${endpoint}`

    const headers: HeadersInit = {
      ...options.headers,
    }

    // Only set JSON Content-Type for non-FormData requests
    if (!(options.body instanceof FormData)) {
      headers["Content-Type"] = "application/json"
    }

    // Add auth token if available
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
      console.log("API request with token:", endpoint, "Token:", this.token.substring(0, 20) + "...")
    } else {
      console.log("API request WITHOUT token:", endpoint)
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      })

      const data = await response.json()

      if (!response.ok) {
        // Handle 401 Unauthorized - trigger login modal
        if (response.status === 401) {
          console.log("401 Unauthorized - clearing token and triggering login")
          // Clear invalid token
          this.token = null
          if (typeof window !== "undefined") {
            localStorage.removeItem("auth_token")
            localStorage.removeItem("user_data")
          }

          // Trigger global login modal
          authEvents.requireLoginModal()
        }

        return {
          success: false,
          message: data.message || `HTTP error! status: ${response.status}`,
          error: data.error || data.detail,
        }
      }

      return {
        success: true,
        message: data.message || "Request successful",
        data: data.data || data,
      }
    } catch (error) {
      console.error("API Request Failed:", {
        url,
        error: error instanceof Error ? error.message : error,
        endpoint
      })

      return {
        success: false,
        message: error instanceof Error ? `Network error: ${error.message}` : "Network error: Unable to connect to server",
        error: error instanceof Error ? error.message : "Unknown error",
      }
    }
  }

  // Authentication methods
  async login(username: string, password: string): Promise<ApiResponse<AuthTokens>> {
    const response = await this.request<AuthTokens>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username,
        password,
      }),
    })

    if (response.success && response.data?.access_token) {
      this.token = response.data.access_token
      if (typeof window !== "undefined") {
        localStorage.setItem("auth_token", this.token)
        localStorage.setItem("user_data", JSON.stringify(response.data.user))
      }
    }

    return response
  }

  async register(userData: {
    username: string
    email: string
    password: string
    full_name?: string
  }): Promise<ApiResponse> {
    return this.request("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(userData),
    })
  }

  async getCurrentUser(): Promise<ApiResponse> {
    console.log('🔍 API: getCurrentUser() called, token exists:', !!this.token);
    if (this.token) {
      console.log('🔍 API: Token preview:', this.token.substring(0, 50) + '...');
    }
    const result = await this.request("/api/v1/auth/me");
    console.log('🔍 API: getCurrentUser() result:', result);
    return result;
  }

  logout(): void {
    this.token = null
    if (typeof window !== "undefined") {
      localStorage.removeItem("auth_token")
      localStorage.removeItem("user_data")
    }
  }

  // System methods
  async getSystemStats(): Promise<ApiResponse<SystemStats>> {
    return this.request<SystemStats>("/api/v1/system/stats/public")
  }

  async getSystemHealth(): Promise<ApiResponse> {
    return this.request("/health")
  }

  // Document methods
  async uploadDocument(file: File, options?: {
    redaction_method?: "blackout" | "blur" | "pixelate" | "replacement"
    output_format?: "same" | "pdf" | "docx"
    sensitivity?: "low" | "medium" | "high"
  }): Promise<ApiResponse<Document>> {
    const formData = new FormData()
    formData.append("file", file)

    if (options) {
      Object.entries(options).forEach(([key, value]) => {
        formData.append(key, value)
      })
    }

    return this.request<Document>("/api/v1/documents/upload", {
      method: "POST",
      headers: {}, // Remove Content-Type for FormData
      body: formData,
    })
  }

  async getDocuments(): Promise<ApiResponse<Document[]>> {
    return this.request<Document[]>("/api/v1/documents")
  }

  async getDocumentPII(documentId: string): Promise<ApiResponse> {
    return this.request(`/api/v1/documents/${documentId}/pii`)
  }

  async downloadRedactedDocument(documentId: string): Promise<Response> {
    const url = `${this.baseURL}/api/v1/documents/${documentId}/download/redacted`
    const headers: HeadersInit = {}

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(url, { headers })

    // Handle 401 for download requests too
    if (response.status === 401) {
      console.log("401 Unauthorized on download - clearing token and triggering login")
      // Clear invalid token
      this.token = null
      if (typeof window !== "undefined") {
        localStorage.removeItem("auth_token")
        localStorage.removeItem("user_data")
      }

      // Trigger global login modal
      authEvents.requireLoginModal()
    }

    return response
  }

  async processDocument(documentId: string, options?: {
    redaction_method?: string
    output_format?: string
    detection_sensitivity?: string
  }): Promise<ApiResponse> {
    return this.request(`/api/v1/documents/${documentId}/process`, {
      method: "POST",
      body: JSON.stringify(options || {}),
    })
  }

  // Job management methods
  async getBatchJobs(): Promise<ApiResponse<BatchJob[]>> {
    return this.request<BatchJob[]>("/api/v1/batch/jobs")
  }

  async createBatchJob(data: {
    name: string
    file_ids: string[]
    priority?: "low" | "medium" | "high"
  }): Promise<ApiResponse<BatchJob>> {
    return this.request<BatchJob>("/api/v1/batch/jobs", {
      method: "POST",
      body: JSON.stringify(data),
    })
  }

  // PII detection methods
  async detectPII(text: string): Promise<ApiResponse> {
    return this.request("/api/v1/pii/detect", {
      method: "POST",
      body: JSON.stringify({ text }),
    })
  }

  async anonymizeText(text: string, entities?: string[]): Promise<ApiResponse> {
    return this.request("/api/v1/pii/anonymize", {
      method: "POST",
      body: JSON.stringify({ text, entities }),
    })
  }

  // Utility methods
  isAuthenticated(): boolean {
    return !!this.token
  }

  getToken(): string | null {
    return this.token
  }

  setToken(token: string): void {
    console.log("API Client: Setting token:", token.substring(0, 20) + "...")
    this.token = token
    if (typeof window !== "undefined") {
      localStorage.setItem("auth_token", token)
    }
  }

  // Settings methods
  async getAllSettings(): Promise<ApiResponse> {
    return this.request("/api/v1/settings/all")
  }

  async getSystemSettings(): Promise<ApiResponse> {
    return this.request("/api/v1/settings/system")
  }

  async updateSystemSettings(updates: any): Promise<ApiResponse> {
    return this.request("/api/v1/settings/system", {
      method: "PUT",
      body: JSON.stringify(updates),
    })
  }

  async getProcessingSettings(): Promise<ApiResponse> {
    return this.request("/api/v1/settings/processing")
  }

  async updateProcessingSettings(updates: any): Promise<ApiResponse> {
    return this.request("/api/v1/settings/processing", {
      method: "PUT",
      body: JSON.stringify(updates),
    })
  }

  async getComplianceSettings(): Promise<ApiResponse> {
    return this.request("/api/v1/settings/compliance")
  }

  async updateComplianceSettings(updates: any): Promise<ApiResponse> {
    return this.request("/api/v1/settings/compliance", {
      method: "PUT",
      body: JSON.stringify(updates),
    })
  }

  async getSecuritySettings(): Promise<ApiResponse> {
    return this.request("/api/v1/settings/security")
  }

  async updateSecuritySettings(updates: any): Promise<ApiResponse> {
    return this.request("/api/v1/settings/security", {
      method: "PUT",
      body: JSON.stringify(updates),
    })
  }

  async getNotificationSettings(): Promise<ApiResponse> {
    return this.request("/api/v1/settings/notifications")
  }

  async updateNotificationSettings(updates: any): Promise<ApiResponse> {
    return this.request("/api/v1/settings/notifications", {
      method: "PUT",
      body: JSON.stringify(updates),
    })
  }
}

// Create singleton instance
const apiClient = new ApiClient()

// Export methods for easy use
export const api = {
  // Auth
  login: (username: string, password: string) => apiClient.login(username, password),
  register: (userData: Parameters<typeof apiClient.register>[0]) => apiClient.register(userData),
  getCurrentUser: () => apiClient.getCurrentUser(),
  logout: () => apiClient.logout(),

  // System
  getSystemStats: () => apiClient.getSystemStats(),
  getSystemHealth: () => apiClient.getSystemHealth(),

  // Documents
  uploadDocument: (file: File, options?: Parameters<typeof apiClient.uploadDocument>[1]) =>
    apiClient.uploadDocument(file, options),
  getDocuments: () => apiClient.getDocuments(),
  getDocumentPII: (documentId: string) => apiClient.getDocumentPII(documentId),
  downloadRedactedDocument: (documentId: string) => apiClient.downloadRedactedDocument(documentId),
  processDocument: (documentId: string, options?: Parameters<typeof apiClient.processDocument>[1]) =>
    apiClient.processDocument(documentId, options),

  // Jobs
  getBatchJobs: () => apiClient.getBatchJobs(),
  createBatchJob: (data: Parameters<typeof apiClient.createBatchJob>[0]) => apiClient.createBatchJob(data),

  // PII
  detectPII: (text: string) => apiClient.detectPII(text),
  anonymizeText: (text: string, entities?: string[]) => apiClient.anonymizeText(text, entities),

  // Settings
  getAllSettings: () => apiClient.getAllSettings(),
  getSystemSettings: () => apiClient.getSystemSettings(),
  updateSystemSettings: (updates: any) => apiClient.updateSystemSettings(updates),
  getProcessingSettings: () => apiClient.getProcessingSettings(),
  updateProcessingSettings: (updates: any) => apiClient.updateProcessingSettings(updates),
  getComplianceSettings: () => apiClient.getComplianceSettings(),
  updateComplianceSettings: (updates: any) => apiClient.updateComplianceSettings(updates),
  getSecuritySettings: () => apiClient.getSecuritySettings(),
  updateSecuritySettings: (updates: any) => apiClient.updateSecuritySettings(updates),
  getNotificationSettings: () => apiClient.getNotificationSettings(),
  updateNotificationSettings: (updates: any) => apiClient.updateNotificationSettings(updates),

  // Utility
  isAuthenticated: () => apiClient.isAuthenticated(),
  getToken: () => apiClient.getToken(),
  setToken: (token: string) => apiClient.setToken(token),
}

export default apiClient
export type { ApiResponse, AuthTokens, SystemStats, Document, BatchJob }