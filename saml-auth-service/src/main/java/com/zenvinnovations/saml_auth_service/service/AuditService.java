package com.zenvinnovations.saml_auth_service.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AuditService {
    
    private static final Logger logger = LoggerFactory.getLogger(AuditService.class);
    
    // Simple in-memory rate limiting (can be replaced with Redis in production)
    private final Map<String, Integer> attemptCounter = new ConcurrentHashMap<>();
    
    public void logAuthenticationAttempt(String clientId, String ipAddress) {
        // Increment attempt counter for rate limiting
        String key = clientId + ":" + ipAddress;
        attemptCounter.merge(key, 1, Integer::sum);
        
        // Log the authentication attempt
        logger.info("Authentication attempt - ClientID: {}, IP: {}, Time: {}", 
                    clientId, ipAddress, LocalDateTime.now());
        
        // Check for suspicious activity (more than 10 attempts in a short period)
        if (attemptCounter.getOrDefault(key, 0) > 10) {
            logger.warn("Suspicious activity detected - ClientID: {}, IP: {}", clientId, ipAddress);
        }
    }
    
    public void logSuccessfulAuthentication(String clientId, String username) {
        logger.info("Successful authentication - ClientID: {}, User: {}, Time: {}", 
                    clientId, username, LocalDateTime.now());
    }
    
    public void logFailedAuthentication(String clientId, String reason) {
        logger.warn("Failed authentication - ClientID: {}, Reason: {}, Time: {}", 
                    clientId, reason, LocalDateTime.now());
    }
    
    // In a production environment, you'd implement methods to:
    // 1. Store audit logs in a database
    // 2. Set up alerts for suspicious activity
    // 3. Create admin APIs to view audit logs
}