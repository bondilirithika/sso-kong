// src/components/Home.js
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import ApiService from '../services/ApiService';
import ConfigService from '../services/ConfigService';

const Home = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    // Check if user is authenticated
    ApiService.getUserInfo()
      .then(userData => {
        setUser(userData);
        setLoading(false);
      })
      .catch(error => {
        console.error("Error checking auth status:", error);
        setLoading(false);
      });
  }, []);
  
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
        
        <div className="mt-4">
          {user ? (
            <>
              <h4>Welcome, {user.email || user.sub}!</h4>
              <div className="d-flex gap-3 mt-3">
                <Link to="/profile" className="btn btn-primary">
                  View Profile
                </Link>
                <Link to="/dashboard" className="btn btn-success">
                  Dashboard
                </Link>
                <a 
                  href={`${ConfigService.getApiBaseUrl()}/logout`}
                  className="btn btn-outline-danger"
                >
                  Logout
                </a>
              </div>
            </>
          ) : (
            <>
              <p>Please login to access protected features.</p>
              <a 
                href={`${ConfigService.getApiBaseUrl()}/auth`}
                className="btn btn-primary"
              >
                Login with Google
              </a>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default Home;