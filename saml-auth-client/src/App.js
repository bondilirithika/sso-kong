// src/App.js
import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';

// Import components
import Header from './components/Header';
import Home from './components/Home';
import Profile from './components/Profile';

function App() {
  // Handle token in URL - just remove it for security
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.has('token')) {
      // Token has been set as HTTP-only cookie by Kong already
      // Just clean the URL for security
      const url = new URL(window.location);
      url.searchParams.delete('token');
      window.history.replaceState({}, '', url);
    }
  }, []);
  
  return (
    <BrowserRouter>
      <div className="d-flex flex-column min-vh-100">
        <Header />
        <div className="flex-grow-1">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/profile" element={<Profile />} />
            {/* Remove Login and Callback routes - not needed anymore */}
          </Routes>
        </div>
        <footer className="bg-light text-center py-3 mt-auto">
          <div className="container">
            <span className="text-muted">SAML Auth Demo &copy; {new Date().getFullYear()}</span>
          </div>
        </footer>
      </div>
    </BrowserRouter>
  );
}

export default App;