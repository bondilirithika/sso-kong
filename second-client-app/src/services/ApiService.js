// src/services/ApiService.js
import ConfigService from './ConfigService';

const ApiService = {
  /**
   * Gets user information from the API
   */
  async getUserInfo() {
    try {
      const response = await fetch(`${ConfigService.getApiBaseUrl()}/api/userinfo`, {
        method: 'GET',
        credentials: 'include', 
        headers: {
          'Accept': 'application/json'
        }
      });
      
      if (response.ok) {
        return await response.json();
      }
      
      return null;
    } catch (error) {
      console.error('API error:', error);
      return null;
    }
  }
};

export default ApiService;