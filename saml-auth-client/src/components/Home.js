// src/components/Home.js
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import AuthService from '../services/AuthService';

const Home = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // Add a short delay to prevent rapid API calls and improve UX
    const checkAuthTimer = setTimeout(() => {
      // Try to get user info
      AuthService.getUserInfo()
        .then(userData => {
          setUser(userData);
          setLoading(false);
        })
        .catch(error => {
          console.error("Error checking auth status:", error);
          setLoading(false); // Make sure we always stop loading
        });
    }, 500); // Short delay for better UX
    
    return () => clearTimeout(checkAuthTimer);
  }, []);
  
  const handleLogin = () => {
    // Use the login method
    AuthService.login();
  };
  
  if (loading) {
    return (
      <div className="container mt-5 text-center">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }
  
  return (
    <div className="container mt-5">
      <div className="jumbotron">
        <h1 className="display-4">Welcome to SAML Auth Demo</h1>
        <p className="lead">
          This application demonstrates SAML-based authentication with Google Workspace via Kong API Gateway.
        </p>
        <hr className="my-4" />
        
        <div className="row">
          <div className="col-md-8">
            <h4>Enterprise SSO Authentication Demo</h4>
            <p>
              This demo showcases how to implement Single Sign-On (SSO) using:
            </p>
            
            <ul className="mb-4">
              <li>SAML 2.0 for authentication with Google Workspace</li>
              <li>Kong API Gateway for centralized security</li>
              <li>Spring Boot for the authentication service</li>
              <li>React for the frontend application</li>
            </ul>
            
            <p className="mb-4">
              Click the Login button to authenticate with Google Workspace, 
              or explore the protected areas to be automatically redirected to login.
            </p>
            
            <div className="d-flex gap-3 mt-4">
              {user ? (
                <>
                  <Link to="/profile" className="btn btn-success btn-lg">
                    View Profile
                  </Link>
                  <button 
                    className="btn btn-outline-danger btn-lg" 
                    onClick={AuthService.logout}
                  >
                    Logout
                  </button>
                </>
              ) : (
                <button 
                  className="btn btn-primary btn-lg" 
                  onClick={handleLogin}
                >
                  Login with Google
                </button>
              )}
              <Link to="/dashboard" className="btn btn-outline-secondary btn-lg">
                View Dashboard
              </Link>
            </div>
          </div>
          <div className="col-md-4 text-center">
            <img 
              src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" 
              alt="Google Logo" 
              style={{ width: '80px', marginBottom: '20px' }}
            />
            <div className="card">
              <div className="card-body">
                <h5 className="card-title">Secure Authentication</h5>
                <p className="card-text">
                  All authentication is handled by Kong API Gateway with tokens stored in HTTP-only cookies.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;