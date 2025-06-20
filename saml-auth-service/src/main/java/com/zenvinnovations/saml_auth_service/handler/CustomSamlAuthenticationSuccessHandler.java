package com.zenvinnovations.saml_auth_service.handler;

import com.zenvinnovations.saml_auth_service.service.JwtService;
import com.zenvinnovations.saml_auth_service.service.AuditService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;
import jakarta.servlet.http.Cookie;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.zenvinnovations.saml_auth_service.controller.EnterpriseAuthController;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Component
public class CustomSamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomSamlAuthenticationSuccessHandler.class);
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private AuditService auditService;
    
    @Value("${auth.default-redirect-url:http://localhost:8000}")
    private String defaultRedirectUrl;
    
    private String findRedirectUrl(HttpServletRequest request) {
        // Default fallback
        String redirectUrl = defaultRedirectUrl;
        logger.debug("Starting redirect URL lookup...");
        
        // First check session
        HttpSession session = request.getSession(false);
        if (session != null) {
            logger.debug("Checking session: {}", session.getId());
            String sessionRedirect = (String) session.getAttribute("redirect_uri");
            if (sessionRedirect != null && !sessionRedirect.isEmpty()) {
                logger.info("Found redirect URL in session (redirect_uri): {}", sessionRedirect);
                return sessionRedirect;
            }
            
            sessionRedirect = (String) session.getAttribute("redirect_after_auth");
            if (sessionRedirect != null && !sessionRedirect.isEmpty()) {
                logger.info("Found redirect URL in session (redirect_after_auth): {}", sessionRedirect);
                return sessionRedirect;
            }
        } else {
            logger.debug("No active session found for redirect lookup");
        }
        
        // Then check cookies as fallback
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            logger.debug("Checking {} cookies", cookies.length);
            for (Cookie cookie : cookies) {
                logger.debug("Examining cookie: {}", cookie.getName());
                if ("auth_redirect_uri".equals(cookie.getName()) || 
                    "redirect_uri".equals(cookie.getName()) || 
                    "return_after_auth".equals(cookie.getName())) {
                    
                    try {
                        // If base64 encoded
                        String value = cookie.getValue();
                        logger.info("Found redirect URL in cookie {}: {}", cookie.getName(), value);
                        try {
                            byte[] decodedBytes = Base64.getDecoder().decode(value);
                            String decodedUri = new String(decodedBytes);
                            logger.info("Successfully decoded redirect URL: {}", decodedUri);
                            
                            // Fix for http://localhost/ vs http://localhost:8000/
                            if (decodedUri.startsWith("http://localhost/")) {
                                decodedUri = decodedUri.replace("http://localhost/", "http://localhost:8000/");
                                logger.info("Fixed URL to use correct port: {}", decodedUri);
                            }
                            
                            return decodedUri;
                        } catch (IllegalArgumentException e) {
                            // Not base64, use as-is
                            logger.info("Using non-base64 cookie value as is: {}", value);
                            return value;
                        }
                    } catch (Exception e) {
                        logger.error("Error processing redirect cookie {}: {}", cookie.getName(), e.getMessage());
                    }
                }
            }
        } else {
            logger.debug("No cookies found for redirect lookup");
        }
        
        logger.info("No redirect URL found, using default: {}", redirectUrl);
        return redirectUrl;
    }
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, 
                                      Authentication authentication) throws IOException {
        logger.info("SAML authentication successful for user: {}", authentication.getName());
        
        // Generate JWT token
        String token = jwtService.generateJwtToken(authentication);
        logger.info("Generated JWT token for user: {}", authentication.getName());
        
        // Log successful authentication
        auditService.logSuccessfulAuthentication("kong", authentication.getName());
        
        // CHANGE THIS LINE to always redirect to Kong
        response.sendRedirect("http://localhost:8000/?token=" + token);
    }
}