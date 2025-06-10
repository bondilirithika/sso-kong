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
      // Check if we already have cached user info
      const cachedInfo = sessionStorage.getItem('user_info');
      if (cachedInfo) {
        return JSON.parse(cachedInfo);
      }
      
      // Call the userinfo endpoint with credentials to send cookies
      const response = await fetch(`${ConfigService.getApiBaseUrl()}/api/userinfo`, {
        credentials: 'include' // Important: This tells fetch to send cookies
      });
      
      if (response.ok) {
        const userData = await response.json();
        // Cache the user data in session storage
        sessionStorage.setItem('user_info', JSON.stringify(userData));
        return userData;
      }
      
      // If we get here, user is not authenticated
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