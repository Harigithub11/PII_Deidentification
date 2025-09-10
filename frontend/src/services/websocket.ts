import { io, Socket } from 'socket.io-client';
import { SystemHealth, WorkerStatus } from '@types/index';

class WebSocketService {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000; // Start with 1 second
  private listeners: Map<string, Set<(data: any) => void>> = new Map();

  constructor() {
    this.connect();
  }

  private connect() {
    const token = localStorage.getItem('token');
    
    this.socket = io('/ws', {
      auth: {
        token,
      },
      transports: ['websocket'],
      upgrade: true,
      rememberUpgrade: true,
    });

    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    if (!this.socket) return;

    this.socket.on('connect', () => {
      console.log('WebSocket connected');
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000;
    });

    this.socket.on('disconnect', (reason) => {
      console.log('WebSocket disconnected:', reason);
      if (reason === 'io server disconnect') {
        // Server initiated disconnect, need to reconnect manually
        this.reconnect();
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('WebSocket connection error:', error);
      this.reconnect();
    });

    // Handle dashboard updates
    this.socket.on('dashboard_update', (data) => {
      this.notifyListeners('dashboard_update', data);
    });

    // Handle job status updates
    this.socket.on('job_status_update', (data) => {
      this.notifyListeners('job_status_update', data);
    });

    // Handle worker status updates
    this.socket.on('worker_status_update', (data) => {
      this.notifyListeners('worker_status_update', data);
    });

    // Handle system health updates
    this.socket.on('system_health_update', (data) => {
      this.notifyListeners('system_health_update', data);
    });

    // Handle upload progress updates
    this.socket.on('upload_progress', (data) => {
      this.notifyListeners('upload_progress', data);
    });

    // Handle workflow updates
    this.socket.on('workflow_update', (data) => {
      this.notifyListeners('workflow_update', data);
    });
  }

  private reconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      this.connect();
    }, delay);
  }

  private notifyListeners(event: string, data: any) {
    const eventListeners = this.listeners.get(event);
    if (eventListeners) {
      eventListeners.forEach(callback => callback(data));
    }
  }

  // Public methods for subscribing to events
  public subscribe(event: string, callback: (data: any) => void) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);

    // Return unsubscribe function
    return () => {
      const eventListeners = this.listeners.get(event);
      if (eventListeners) {
        eventListeners.delete(callback);
      }
    };
  }

  // Dashboard-specific subscriptions
  public subscribeToDashboard(dashboardId: string, callback: (data: any) => void) {
    if (this.socket) {
      this.socket.emit('subscribe_dashboard', { dashboard_id: dashboardId });
    }
    return this.subscribe('dashboard_update', (data) => {
      if (data.dashboard_id === dashboardId) {
        callback(data);
      }
    });
  }

  public unsubscribeFromDashboard(dashboardId: string) {
    if (this.socket) {
      this.socket.emit('unsubscribe_dashboard', { dashboard_id: dashboardId });
    }
  }

  // Job monitoring subscriptions
  public subscribeToJobUpdates(callback: (data: any) => void) {
    return this.subscribe('job_status_update', callback);
  }

  public subscribeToWorkerUpdates(callback: (data: any) => void) {
    return this.subscribe('worker_status_update', callback);
  }

  public subscribeToSystemHealth(callback: (data: any) => void) {
    return this.subscribe('system_health_update', callback);
  }

  public subscribeToUploadProgress(callback: (data: any) => void) {
    return this.subscribe('upload_progress', callback);
  }

  // Additional methods needed by components
  public subscribeToJobs(callback: (data: any) => void) {
    return this.subscribe('job_status_update', callback);
  }

  public subscribeToSystemMetrics(callback: (data: any) => void) {
    return this.subscribe('system_health_update', callback);
  }

  public subscribeToWorkerStatus(callback: (data: any) => void) {
    return this.subscribe('worker_status_update', callback);
  }

  // Send messages to server
  public emit(event: string, data: any) {
    if (this.socket && this.socket.connected) {
      this.socket.emit(event, data);
    } else {
      console.warn('WebSocket not connected, cannot emit:', event);
    }
  }

  // Connection status
  public isConnected(): boolean {
    return this.socket?.connected ?? false;
  }

  // Cleanup
  public disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    this.listeners.clear();
  }

  // Update authentication token
  public updateAuth(token: string) {
    if (this.socket) {
      this.socket.auth = { token };
      this.socket.connect();
    }
  }
}

// Create singleton instance
export const websocketService = new WebSocketService();

// React hook for using WebSocket in components
export const useWebSocket = () => {
  return {
    subscribe: websocketService.subscribe.bind(websocketService),
    subscribeToDashboard: websocketService.subscribeToDashboard.bind(websocketService),
    unsubscribeFromDashboard: websocketService.unsubscribeFromDashboard.bind(websocketService),
    subscribeToJobUpdates: websocketService.subscribeToJobUpdates.bind(websocketService),
    subscribeToWorkerUpdates: websocketService.subscribeToWorkerUpdates.bind(websocketService),
    subscribeToSystemHealth: websocketService.subscribeToSystemHealth.bind(websocketService),
    subscribeToUploadProgress: websocketService.subscribeToUploadProgress.bind(websocketService),
    emit: websocketService.emit.bind(websocketService),
    isConnected: websocketService.isConnected.bind(websocketService),
  };
};