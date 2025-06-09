package com.zenvinnovations.saml_auth_service.handler;

import com.zenvinnovations.saml_auth_service.service.JwtService;
import com.zenvinnovations.saml_auth_service.service.AuditService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
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
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, 
                                      Authentication authentication) throws IOException {
        logger.info("SAML authentication successful for user: {}", authentication.getName());
        
        // Store authentication in session
        HttpSession session = request.getSession(true);
        session.setAttribute("authenticated_user", authentication.getName());
        
        // Get redirect URL from session or use fallback
        String redirectUrl = "http://localhost:8000";
        String sessionRedirect = (String) session.getAttribute("redirect_after_auth");
        if (sessionRedirect != null && !sessionRedirect.isEmpty()) {
            redirectUrl = sessionRedirect;
            logger.info("Using redirect URL from session: {}", redirectUrl);
        } else {
            logger.warn("No redirect_after_auth in session, using fallback URL: {}", redirectUrl);
        }
        
        // Generate JWT token
        String token = jwtService.generateJwtToken(authentication);
        logger.info("Generated JWT token for user: {}", authentication.getName());
        
        // Log successful authentication
        auditService.logSuccessfulAuthentication("kong", authentication.getName());
        
        // Build final URL with token
        StringBuilder finalUrl = new StringBuilder(redirectUrl);
        if (redirectUrl.contains("?")) {
            finalUrl.append("&token=").append(token);
        } else {
            finalUrl.append("?token=").append(token);
        }
        
        // Add state if it was provided
        String state = (String) session.getAttribute("oauth_state");
        if (state != null && !state.isEmpty()) {
            finalUrl.append("&state=").append(state);
        }
        
        String logUrl = finalUrl.toString().replaceAll("token=.*?(&|$)", "token=REDACTED$1");
        logger.info("Redirecting to: {}", logUrl);
        
        // Redirect to final URL with token
        response.sendRedirect(finalUrl.toString());
    }
}