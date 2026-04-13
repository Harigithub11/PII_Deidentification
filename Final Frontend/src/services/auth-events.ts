// Event system for authentication state management across the app

type AuthEventListener = () => void

class AuthEvents {
  private loginRequiredListeners: AuthEventListener[] = []

  // Register a listener for when login is required
  onLoginRequired(callback: AuthEventListener) {
    this.loginRequiredListeners.push(callback)

    // Return unsubscribe function
    return () => {
      const index = this.loginRequiredListeners.indexOf(callback)
      if (index > -1) {
        this.loginRequiredListeners.splice(index, 1)
      }
    }
  }

  // Trigger login modal requirement
  requireLoginModal() {
    console.log('🚨 AuthEvents: Triggering login requirement, listeners count:', this.loginRequiredListeners.length)
    console.trace('🚨 AuthEvents: Stack trace for login requirement');
    this.loginRequiredListeners.forEach(listener => {
      try {
        listener()
      } catch (error) {
        console.error('Error in auth event listener:', error)
      }
    })
  }
}

// Create singleton instance
export const authEvents = new AuthEvents()

export default authEvents