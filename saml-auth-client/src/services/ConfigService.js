// src/services/ConfigService.js
const ConfigService = {
  getApiBaseUrl: () => process.env.REACT_APP_API_URL || ''
};
export default ConfigService;