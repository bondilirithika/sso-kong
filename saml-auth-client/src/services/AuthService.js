// src/services/AuthService.js
import ConfigService from './ConfigService';

/**
 * Simplified authentication service that relies on Kong
 */
const AuthService = {
  /**
   * Gets the current user information from the API
   * The browser automatically sends the HTTP-only cookie
   */
  async getUserInfo() {
    try {
      console.log("Fetching user info...");
      const response = await fetch(`${ConfigService.getApiBaseUrl()}/api/userinfo`, {
        method: 'GET',
        credentials: 'include', // This is critical for including cookies
        headers: {
          'Accept': 'application/json'
        }
      });
      
      console.log("Response status:", response.status);
      
      if (response.ok) {
        const userData = await response.json();
        console.log("User data received:", userData);
        return userData;
      }
      console.log("Failed to get user data");
      return null;
    } catch (error) {
      console.error('Error checking authentication:', error);
      return null;
    }
  },
  
  /**
   * Initiates login flow through Kong
   */
  login() {
    // Get current URL to redirect back after login
    const currentUrl = window.location.href;
    const encodedUrl = btoa(currentUrl);
    
    // Redirect to auth through Kong
    window.location.href = `${ConfigService.getApiBaseUrl()}/auth?redirect_uri=${encodedUrl}`;
  },
  
  /**
   * Logs the user out by calling logout endpoint
   */
  logout() {
    // Clear local cache
    sessionStorage.removeItem('user_info');
    
    // Call logout endpoint
    window.location.href = `${ConfigService.getApiBaseUrl()}/logout`;
  }
};

export default AuthService;