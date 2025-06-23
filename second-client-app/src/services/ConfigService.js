// src/services/ConfigService.js
const ConfigService = {
  getApiBaseUrl() {
    // Always use localhost:8000 for Kong
    return 'http://localhost:8000';
  },
  
  // Important: When accessing through Kong, the app is mounted at /app2
  getAppBasePath() {
    // When accessed via Kong, we're at /app2
    // For direct development access, we're at /
    const isDirectAccess = window.location.port === '3001';
    return isDirectAccess ? '' : '/app2';
  },
  
  // Combine the API base URL with a path
  getApiUrl(path) {
    return `${this.getApiBaseUrl()}${path}`;
  },
  
  // For development and debugging
  getEnvironment() {
    return process.env.REACT_APP_ENV || 'development';
  }
};

export default ConfigService;