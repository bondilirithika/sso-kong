// src/services/ConfigService.js
const ConfigService = {
  // Make sure this returns "http://localhost:8000" and not something else
  getApiBaseUrl() {
    return process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";
  },
  
  getAuthUrl() {
    // Keep ngrok URL for server-to-server communication
    return process.env.REACT_APP_AUTH_URL || 'https://overseas-juice-helping-dividend.trycloudflare.com';
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