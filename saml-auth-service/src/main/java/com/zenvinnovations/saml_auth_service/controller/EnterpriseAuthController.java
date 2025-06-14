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
import java.util.Base64;
import java.util.List;
import java.net.URL;

@Controller
public class EnterpriseAuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(EnterpriseAuthController.class);
    
    @Value("${auth.allowed-domains}")
    private String allowedDomains;
    
    @Value("${auth.default-redirect-url}")
    private String defaultRedirectUrl;
    
    @Autowired
    private AuditService auditService;
    
    @GetMapping("/auth")
    public RedirectView initiateAuth(
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String state,
            HttpServletRequest request) {
        
        logger.info("Authentication request received for redirect_uri: {}", redirect_uri);
        
        HttpSession session = request.getSession(true);
        String decodedUri = null;
        
        // Get session ID for tracking
        logger.info("Session ID created: {}", session.getId());
        
        if (redirect_uri != null && !redirect_uri.isEmpty()) {
            try {
                // Try to decode if it's base64
                byte[] decodedBytes = Base64.getDecoder().decode(redirect_uri);
                decodedUri = new String(decodedBytes);
                logger.debug("Decoded redirect URI from Base64: {}", decodedUri);
            } catch (IllegalArgumentException e) {
                // If not base64, use as is
                decodedUri = redirect_uri;
                logger.debug("Using redirect URI as is (not Base64): {}", decodedUri);
            }
            
            // Store in both attributes for compatibility
            session.setAttribute("redirect_uri", decodedUri);
            session.setAttribute("redirect_after_auth", decodedUri);
            logger.info("Stored redirect_uri in session: {}", decodedUri);
        } else {
            logger.warn("No redirect_uri provided, using default");
            session.setAttribute("redirect_uri", defaultRedirectUrl);
            session.setAttribute("redirect_after_auth", defaultRedirectUrl);
        }
        
        // Store state if provided
        if (state != null && !state.isEmpty()) {
            session.setAttribute("oauth_state", state);
            logger.debug("Stored oauth_state in session: {}", state);
        }
        
        return new RedirectView("/saml2/authenticate/google-workspace");
    }
    
    private boolean isValidRedirectUri(String uri) {
        try {
            // Parse the URI to extract host
            URL url = new URL(uri);
            String host = url.getHost();
            
            // Get allowed domains from configuration
            List<String> domains = Arrays.asList(allowedDomains.split(","));
            
            // Enhanced check: host must exactly match domain or be a subdomain
            return domains.stream().anyMatch(domain -> 
                host.equals(domain) || host.endsWith("." + domain));
        } catch (Exception e) {
            logger.error("Error validating redirect URI: {}", e.getMessage(), e);
            return false;
        }
    }
}