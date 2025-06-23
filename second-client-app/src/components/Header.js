// src/components/Header.js
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import ApiService from '../services/ApiService';
import ConfigService from '../services/ConfigService';

const Header = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    ApiService.getUserInfo()
      .then(userData => {
        console.log("User data:", userData); // Debug
        setUser(userData);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error fetching user data:', error);
        setLoading(false);
      });
  }, []);
  
  // Helper to create correct links with base path
  const appLink = (path) => {
    return `${ConfigService.getAppBasePath()}${path}`;
  };
  
  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-success">
      <div className="container">
        <Link to={appLink('/')} className="navbar-brand">Second App</Link>
        
        <div className="collapse navbar-collapse">
          <ul className="navbar-nav me-auto">
            <li className="nav-item">
              <Link to={appLink('/')} className="nav-link">Home</Link>
            </li>
            {user && (
              <>
                <li className="nav-item">
                  <Link to={appLink('/dashboard')} className="nav-link">Dashboard</Link>
                </li>
                <li className="nav-item">
                  <Link to={appLink('/settings')} className="nav-link">Settings</Link>
                </li>
              </>
            )}
          </ul>
          
          {loading ? (
            <div className="spinner-border spinner-border-sm text-light" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          ) : user ? (
            <div className="d-flex">
              <span className="navbar-text me-3">{user.email}</span>
              <a 
                href={`${ConfigService.getApiBaseUrl()}/logout?redirect_to=${encodeURIComponent("http://localhost:8000/app2")}`}
                className="btn btn-outline-light btn-sm"
              >
                Logout
              </a>
              
            </div>
          ) : (
            <a 
              href={`${ConfigService.getApiBaseUrl()}/auth`}
              className="btn btn-outline-light"
            >
              Login
            </a>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Header;