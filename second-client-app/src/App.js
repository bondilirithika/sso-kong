import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';
import ConfigService from './services/ConfigService';

// Import components
import Header from './components/Header';
import Home from './components/Home';
import Dashboard from './components/Dashboard';
import Settings from './components/Settings';

function App() {
  // Handle token in URL - remove it for security
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has('token')) {
      // Token has been set as HTTP-only cookie by Kong already
      // Clean the URL for security
      const url = new URL(window.location);
      url.searchParams.delete('token');
      window.history.replaceState({}, '', url);
    }
  }, []);
  
  // Get base path from environment or use /app2 if behind Kong
  const basePath = process.env.PUBLIC_URL || '/app2';
  
  return (
    <BrowserRouter basename={basePath}>
      <div className="d-flex flex-column min-vh-100">
        <Header />
        <div className="flex-grow-1">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </div>
        <footer className="bg-light text-center py-3 mt-auto">
          <div className="container">
            <span className="text-muted">Second App Demo &copy; {new Date().getFullYear()}</span>
          </div>
        </footer>
      </div>
    </BrowserRouter>
  );
}

export default App;
