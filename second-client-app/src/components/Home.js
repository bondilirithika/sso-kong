// src/components/Home.js
import React from 'react';
import { Link } from 'react-router-dom';
import ConfigService from '../services/ConfigService';

const Home = () => {
  return (
    <div className="container mt-5">
      <div className="jumbotron">
        <h1 className="display-4">Welcome to Second App</h1>
        <p className="lead">
          This is another application using the same SSO system.
        </p>
        <hr className="my-4" />
        <p>Login to access protected features.</p>
        <a 
          href={`${ConfigService.getApiBaseUrl()}/auth`}
          className="btn btn-success"
        >
          Login with Google
        </a>
      </div>
    </div>
  );
};

export default Home;