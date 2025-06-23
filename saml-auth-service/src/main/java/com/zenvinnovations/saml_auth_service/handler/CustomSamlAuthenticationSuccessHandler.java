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
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Component
public class CustomSamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomSamlAuthenticationSuccessHandler.class);
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private AuditService auditService;
    
    @Value("${auth.default-redirect-url:http://localhost:8000}")
    private String defaultRedirectUrl;
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, 
                                      Authentication authentication) throws IOException {
        logger.info("SAML authentication successful for user: {}", authentication.getName());
        
        // Generate JWT token
        String token = jwtService.generateJwtToken(authentication);
        logger.info("Generated JWT token for user: {}", authentication.getName());
        
        // Log successful authentication
        auditService.logSuccessfulAuthentication("kong", authentication.getName());
        
        // Always redirect to Kong with the token - Kong handles the redirect after authentication
        response.sendRedirect("http://localhost:8000/?token=" + token);
    }
}