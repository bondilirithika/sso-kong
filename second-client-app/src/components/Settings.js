// src/components/Settings.js
import React, { useState, useEffect } from 'react';
import ApiService from '../services/ApiService';

const Settings = () => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    ApiService.getUserInfo()
      .then(userData => {
        setUser(userData);
        setLoading(false);
      })
      .catch(error => {
        console.error("Error loading user data:", error);
        setLoading(false);
      });
  }, []);

  if (loading) {
    return (
      <div className="container mt-5 text-center">
        <div className="spinner-border text-success" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="container mt-5">
      <div className="card">
        <div className="card-header bg-success text-white">
          <h3 className="mb-0">Settings</h3>
        </div>
        <div className="card-body">
          <h4>User Settings</h4>
          <p>Email: {user?.email || 'Not available'}</p>
          <p>This is another protected page in the second application.</p>
        </div>
      </div>
    </div>
  );
};

export default Settings;