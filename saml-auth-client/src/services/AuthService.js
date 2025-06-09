// src/services/AuthService.js
import ConfigService from './ConfigService';

/**
 * Helper function to decode JWT tokens
 */
const parseJwt = (token) => {
  try {
    // Split the token and get the payload part
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    console.error('Error parsing JWT:', e);
    return null;
  }
};

/**
 * Minimal authentication service that relies on Kong for most functionality
 */
const AuthService = {
  /**
   * Gets the current user information
   * @returns {Promise<Object|null>} User information
   */
  async getUserInfo() {
    try {
      // First, check if we already have auth info in sessionStorage
      const authInfo = sessionStorage.getItem('auth_info');
      if (authInfo) {
        return JSON.parse(authInfo);
      }
      
      // Then check for token in URL - this means we just got redirected back
      const urlParams = new URLSearchParams(window.location.search);
      const token = urlParams.get('token');
      
      // If we have a token in the URL, we've successfully authenticated
      if (token) {
        // Clean up URL to remove token
        const newUrl = window.location.href.split('?')[0];
        window.history.replaceState({}, document.title, newUrl);
        
        // Decode the token to extract user info
        const decodedToken = parseJwt(token);
        if (decodedToken) {
          // Create a user object with data from token
          const user = {
            ...decodedToken,
            authenticated: true
          };
          
          // Store in sessionStorage
          sessionStorage.setItem('auth_info', JSON.stringify(user));
          return user;
        }
      }
      
      // Try to get user info from backend with cookies
      try {
        const response = await fetch(`${ConfigService.getApiBaseUrl()}/api/userinfo`, {
          credentials: 'include',
          headers: {
            'Accept': 'application/json'
          }
        });
        
        if (response.ok) {
          const userData = await response.json();
          sessionStorage.setItem('auth_info', JSON.stringify(userData));
          return userData;
        }
        
        // Handle 401 responses gracefully - this is key!
        if (response.status === 401) {
          console.log("Not authenticated (401 response)");
          return null;
        }
      } catch (error) {
        console.log("Not authenticated, silently continuing");
      }
      
      return null;
    } catch (error) {
      console.error('Error in auth flow:', error);
      return null;
    }
  },
  
  /**
   * Explicitly trigger login - only called when login button is clicked
   */
  login() {
    // IMPORTANT: This directly triggers SAML auth with the right redirect
    window.location.href = "https://6e00-122-175-23-214.ngrok-free.app/auth?redirect_uri=" + 
      btoa("http://localhost:8000"); // Base64 encode the redirect URL
  },
  
  /**
   * Logs the user out
   */
  logout() {
    // Clear auth info
    sessionStorage.removeItem('auth_info');
    
    // Redirect to logout
    window.location.href = `${ConfigService.getApiBaseUrl()}/logout`;
  }
};

export default AuthService;