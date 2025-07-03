// src/components/Header.js
import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import ApiService from '../services/ApiService';
import ConfigService from '../services/ConfigService';

const Header = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const location = useLocation();
  
  useEffect(() => {
    const checkAuth = async () => {
      try {
        const userData = await ApiService.getUserInfo();
        setUser(userData);
      } catch (error) {
        console.error("Error checking auth status:", error);
      } finally {
        setLoading(false);
      }
    };
    
    checkAuth();
  }, [location.pathname]);
  
  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-primary">
      <div className="container">
        <Link to="/" className="navbar-brand">SAML Auth Demo</Link>
        <button className="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav me-auto">
            <li className="nav-item">
              <Link to="/" className="nav-link">Home</Link>
            </li>
            {user && (
              <>
                <li className="nav-item">
                  <Link to="/dashboard" className="nav-link">Dashboard</Link>
                </li>
                <li className="nav-item">
                  <Link to="/profile" className="nav-link">Profile</Link>
                </li>
              </>
            )}
          </ul>
          
          {loading ? (
            <div className="spinner-border spinner-border-sm text-light" role="status">
              <span className="visually-hidden">Loading...</span>
            </div>
          ) : user ? (
            <ul className="navbar-nav">
              <li className="nav-item">
                <span className="nav-link">{user.email || user.sub}</span>
              </li>
              <li className="nav-item">
                <a 
                  href={`${ConfigService.getApiBaseUrl()}/custom-logout?redirect_to=${encodeURIComponent(window.location.origin)}`}
                  className="btn btn-link nav-link"
                >
                  Logout
                </a>
              </li>
            </ul>
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