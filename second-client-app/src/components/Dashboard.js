// src/components/Dashboard.js
import React, { useState, useEffect } from 'react';
import ApiService from '../services/ApiService';

const Dashboard = () => {
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
          <h3 className="mb-0">Second App Dashboard</h3>
        </div>
        <div className="card-body">
          <h4>Welcome, {user?.name || user?.email || 'User'}</h4>
          <p>This is your protected dashboard in the second application.</p>
          <p>You are authenticated across multiple applications with a single login!</p>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;