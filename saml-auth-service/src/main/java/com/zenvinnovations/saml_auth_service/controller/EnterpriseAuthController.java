package com.zenvinnovations.saml_auth_service.controller;

import com.zenvinnovations.saml_auth_service.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Arrays;
import java.util.List;

@Controller
public class EnterpriseAuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(EnterpriseAuthController.class);
    
    @Value("${auth.allowed-domains}")
    private String allowedDomains;
    
    @Autowired
    private AuditService auditService;
    
    @GetMapping("/auth")
    public RedirectView initiateAuth(
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String state,
            HttpServletRequest request) {
        
        // If no redirect_uri is provided, check if user is already authenticated
        if (redirect_uri == null || redirect_uri.isEmpty()) {
            // Check if user is already authenticated
            Object user = request.getSession(false) != null ? 
                request.getSession(false).getAttribute("authenticated_user") : null;
                
            if (user != null) {
                logger.info("User already authenticated, redirecting to home: {}", user);
                return new RedirectView("http://localhost:3000");
            }
            
            // If not authenticated and no redirect_uri, use default
            logger.warn("No redirect_uri provided, using default");
            redirect_uri = "aHR0cDovL2xvY2FsaG9zdDo4MDAw"; // Base64 encoded "http://localhost:8000"
        }
        
        logger.info("Authentication request received for redirect_uri: {}", redirect_uri);
        
        // Try to decode if it's Base64
        String decodedUri = redirect_uri;
        try {
            if (redirect_uri.matches("^[A-Za-z0-9+/=]+$")) {
                decodedUri = new String(java.util.Base64.getDecoder().decode(redirect_uri), java.nio.charset.StandardCharsets.UTF_8);
                logger.debug("Decoded redirect URI from Base64: {}", decodedUri);
            }
        } catch (IllegalArgumentException e) {
            logger.debug("Redirect URI is not valid Base64, using as is");
        }
        
        // Validate redirect_uri to prevent open redirect vulnerabilities
        if (!isValidRedirectUri(decodedUri)) {
            logger.warn("Invalid redirect_uri: {}", decodedUri);
            return new RedirectView("/error?code=invalid_redirect");
        }
        
        // Create a new session
        HttpSession session = request.getSession(true);
        
        // Store the decoded redirect_uri in session
        session.setAttribute("redirect_after_auth", decodedUri);
        logger.info("Stored redirect_uri in session: {}", decodedUri);
        
        // Store state for CSRF protection if provided
        if (state != null && !state.isEmpty()) {
            session.setAttribute("oauth_state", state);
        }

        // Set longer session timeout
        session.setMaxInactiveInterval(3600); // 1 hour
        
        // Log session ID for debugging
        logger.info("Session ID created: {}", session.getId());
        
        // Redirect directly to SAML authentication - bypass Spring Security's login page
        return new RedirectView("/saml2/authenticate/google-workspace");
    }
    
    private boolean isValidRedirectUri(String uri) {
        if (uri == null || uri.trim().isEmpty()) {
            return false;
        }
        
        // Get allowed domains from configuration
        List<String> domains = Arrays.asList(allowedDomains.split(","));
        
        // Check if URI contains any allowed domain
        return domains.stream().anyMatch(uri::contains);
    }
}