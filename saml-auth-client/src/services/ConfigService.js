// src/services/ConfigService.js
const ConfigService = {
  getApiBaseUrl() {
    return process.env.REACT_APP_API_URL || 'http://localhost:8000';
  },
  
  getAuthUrl() {
    return process.env.REACT_APP_AUTH_URL || 'https://6e00-122-175-23-214.ngrok-free.app';
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