// Common types used throughout the application
export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  last_login?: string;
  permissions: string[];
  phone?: string;
  organization?: string;
  timezone?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

// Batch Job Types
export interface BatchJob {
  id: string;
  name: string;
  description?: string;
  job_type: BatchJobType;
  status: BatchJobStatus;
  priority: JobPriority;
  progress_percentage: number;
  current_step: string;
  steps_completed: number;
  total_steps: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  created_by: string;
  assigned_to?: string;
  parameters: Record<string, any>;
  result_summary: Record<string, any>;
  error_message?: string;
  timeout_seconds: number;
  retry_count: number;
  max_retries: number;
  duration_seconds?: number;
}

export enum BatchJobType {
  DOCUMENT_PROCESSING = 'document_processing',
  PII_DETECTION = 'pii_detection',
  BULK_REDACTION = 'bulk_redaction',
  COMPLIANCE_VALIDATION = 'compliance_validation',
  AUDIT_GENERATION = 'audit_generation',
  BULK_ENCRYPTION = 'bulk_encryption',
  POLICY_APPLICATION = 'policy_application',
  REPORT_GENERATION = 'report_generation',
  CUSTOM = 'custom'
}

export enum BatchJobStatus {
  PENDING = 'pending',
  QUEUED = 'queued',
  RUNNING = 'running',
  PAUSED = 'paused',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
  TIMEOUT = 'timeout'
}

export enum JobPriority {
  LOW = 'low',
  NORMAL = 'normal',
  HIGH = 'high',
  CRITICAL = 'critical',
  URGENT = 'urgent'
}

// Worker Types
export interface BatchWorker {
  id: string;
  worker_name: string;
  hostname: string;
  status: WorkerStatusEnum;
  current_jobs_count: number;
  max_concurrent_jobs: number;
  cpu_usage?: number;
  memory_usage?: number;
  memory_limit: number;
  last_heartbeat?: string;
  success_rate?: number;
}

export enum WorkerStatusEnum {
  IDLE = 'idle',
  BUSY = 'busy',
  OFFLINE = 'offline',
  ERROR = 'error',
  MAINTENANCE = 'maintenance'
}

// Dashboard Widget Types
export interface DashboardWidget {
  id: string;
  type: WidgetType;
  title: string;
  description?: string;
  config: Record<string, any>;
  position: {
    x: number;
    y: number;
    w: number;
    h: number;
  };
}

export enum WidgetType {
  BATCH_JOB_QUEUE = 'batch_job_queue',
  BATCH_WORKER_STATUS = 'batch_worker_status',
  BATCH_JOB_METRICS = 'batch_job_metrics',
  BATCH_SCHEDULE_STATUS = 'batch_schedule_status',
  AIRFLOW_DAG_STATUS = 'airflow_dag_status',
  WORKFLOW_EXECUTION_CHART = 'workflow_execution_chart',
  JOB_PERFORMANCE_METRICS = 'job_performance_metrics',
  SYSTEM_HEALTH_MONITOR = 'system_health_monitor',
  METRIC = 'metric',
  CHART = 'chart',
  TABLE = 'table'
}

// File Upload Types
export interface UploadFile {
  id: string;
  file: File;
  name: string;
  size: number;
  type: string;
  status: UploadStatus;
  progress: number;
  error?: string;
  preview?: string;
  jobId?: string;
}

export enum UploadStatus {
  PENDING = 'pending',
  UPLOADING = 'uploading',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

// Workflow Types
export interface WorkflowDefinition {
  id: string;
  name: string;
  description?: string;
  version: string;
  status: WorkflowStatus;
  steps: WorkflowStep[];
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface WorkflowStep {
  id: string;
  name: string;
  type: WorkflowStepType;
  parameters: Record<string, any>;
  position: { x: number; y: number };
  connections: string[];
}

export enum WorkflowStepType {
  BATCH_JOB = 'batch_job',
  CONDITION = 'condition',
  DELAY = 'delay',
  NOTIFICATION = 'notification',
  WEBHOOK = 'webhook'
}

export enum WorkflowStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  PAUSED = 'paused',
  ARCHIVED = 'archived'
}

// API Response Types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

// Notification Types
export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  action?: {
    label: string;
    url: string;
  };
}

export type NotificationType = 'info' | 'success' | 'warning' | 'error';

// Theme and UI Types
export interface ThemeConfig {
  mode: 'light' | 'dark';
  primaryColor: string;
  secondaryColor: string;
}

export interface UIState {
  sidebarOpen: boolean;
  theme: ThemeConfig;
  notifications: Notification[];
  loading: boolean;
}

// WebSocket Message Types
export interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: string;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'critical';
  components: Record<string, ComponentStatus>;
  alerts: Alert[];
}

export interface ComponentStatus {
  status: 'healthy' | 'warning' | 'error';
  last_check: string;
  message?: string;
}

export interface Alert {
  severity: 'info' | 'warning' | 'error' | 'critical';
  message: string;
  timestamp: string;
  acknowledged?: boolean;
}

// Additional missing types for components
export interface DashboardStats {
  total_jobs: number;
  jobs_this_week: number;
  total_documents: number;
  documents_processed_today: number;
  pii_entities_found: number;
  redaction_accuracy: number;
  system_load_percentage: number;
  overall_status: string;
  uptime: string;
  recent_alerts: Array<{
    timestamp: string;
    severity: string;
    component: string;
    message: string;
  }>;
}

export interface RecentActivity {
  id: string;
  title: string;
  description: string;
  timestamp: string;
}

export interface JobFilter {
  status?: string;
  job_type?: string;
  priority?: string;
  created_by?: string;
  date_from?: string;
  date_to?: string;
}

export interface BatchJobConfig {
  name: string;
  job_type: string;
  priority: string;
  policy_id: string;
  settings: {
    output_format: string;
    redaction_method: string;
    preserve_formatting: boolean;
    include_confidence_scores: boolean;
  };
}

export interface FileUpload {
  id: string;
  filename: string;
  original_name: string;
  file_size: number;
  file_type: string;
  upload_time: string;
  status: string;
}

export interface PolicyConfiguration {
  id: string;
  name: string;
  description: string;
  version: string;
  enabled_entities: string[];
  confidence_threshold: number;
  redaction_method: string;
  created_at: string;
  is_active: boolean;
}

export interface SystemMetrics {
  cpu_usage: number;
  memory_usage: number;
  disk_io: number;
  system_load_percentage: number;
  overall_status: string;
  uptime: string;
  recent_alerts: Array<{
    timestamp: string;
    severity: string;
    component: string;
    message: string;
  }>;
}

export interface WorkerStatus {
  worker_id: string;
  worker_name: string;
  status: string;
  current_load: number;
  last_heartbeat: string;
}

export interface PerformanceData {
  timestamps: string[];
  cpu_history: number[];
  memory_history: number[];
  throughput_history: number[];
  error_rate_history: number[];
}

export interface UserProfile {
  full_name: string;
  email: string;
  phone: string;
  organization: string;
  timezone: string;
}

export interface SystemSettings {
  max_concurrent_jobs: number;
  job_timeout_minutes: number;
  auto_cleanup_days: number;
  enable_notifications: boolean;
  notification_email: boolean;
  notification_webhook: boolean;
  webhook_url: string;
  storage_retention_days: number;
  max_file_size_mb: number;
  allowed_file_types: string[];
}

export interface ApiKey {
  id: string;
  name: string;
  created_at: string;
  last_used?: string;
  is_active: boolean;
}