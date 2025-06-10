// src/services/ConfigService.js
const ConfigService = {
  getApiBaseUrl() {
    return process.env.REACT_APP_API_URL || 'http://localhost:8000';
  }
};

export default ConfigService;