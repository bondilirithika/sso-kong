// src/services/ConfigService.js
const ConfigService = {
  getApiBaseUrl() {
    // Always use localhost:8000 for browser-based requests
    return 'http://localhost:8000';
  },
  
  getAuthUrl() {
    // Keep ngrok URL for server-to-server communication
    return process.env.REACT_APP_AUTH_URL || 'https://9a96-122-171-174-91.ngrok-free.app';
  },
  
  // For debugging and future expansions
  getEnvironment() {
    return process.env.REACT_APP_ENV || 'development';
  },
  
  isDevelopment() {
    return this.getEnvironment() === 'development';
  }
};

export default ConfigService;