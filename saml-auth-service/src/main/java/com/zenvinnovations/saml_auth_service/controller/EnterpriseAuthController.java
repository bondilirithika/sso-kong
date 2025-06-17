package com.zenvinnovations.saml_auth_service.controller;

import com.zenvinnovations.saml_auth_service.service.AuditService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URL;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Controller
public class EnterpriseAuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(EnterpriseAuthController.class);
    
    @Value("${auth.allowed-domains}")
    private String allowedDomains;
    
    @Value("${auth.default-redirect-url}")
    private String defaultRedirectUrl;
    
    @Autowired
    private AuditService auditService;
    
    // Add this code at the top of the class
    private static final Map<String, Map<String, String>> REDIRECT_CACHE = new ConcurrentHashMap<>();
    
    @GetMapping("/auth")
    public RedirectView initiateAuth(
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String state,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        logger.info("Authentication request received for redirect_uri: {}", redirect_uri);
        
        // Get existing session instead of always creating a new one
        HttpSession session = request.getSession(false);
        if (session == null) {
            session = request.getSession(true);
            logger.info("New session created: {}", session.getId());
        } else {
            logger.info("Using existing session: {}", session.getId());
        }
        
        String decodedUri = null;
        
        if (redirect_uri != null && !redirect_uri.isEmpty()) {
            try {
                // Try to decode if it's base64
                byte[] decodedBytes = Base64.getDecoder().decode(redirect_uri);
                decodedUri = new String(decodedBytes);
                logger.debug("Decoded redirect URI from Base64: {}", decodedUri);
                
                // Fix for http://localhost/ vs http://localhost:8000/
                if (decodedUri.startsWith("http://localhost/")) {
                    decodedUri = decodedUri.replace("http://localhost/", "http://localhost:8000/");
                    logger.info("Fixed redirect URI to use correct port: {}", decodedUri);
                }
            } catch (IllegalArgumentException e) {
                // If not base64, use as is
                decodedUri = redirect_uri;
                logger.debug("Using redirect URI as is (not Base64): {}", decodedUri);
            }
            
            // Store in session
            session.setAttribute("redirect_uri", decodedUri);
            session.setAttribute("redirect_after_auth", decodedUri);
            logger.info("Stored redirect_uri in session: {}", decodedUri);
            
            // Simplify cookie storage - use a single standardized cookie
            Cookie redirectCookie = new Cookie("auth_redirect_uri", redirect_uri);
            redirectCookie.setPath("/");
            redirectCookie.setMaxAge(300); // 5 minutes
            redirectCookie.setHttpOnly(true);
            response.addCookie(redirectCookie);
            
            logger.debug("Stored redirect cookie: {}", redirect_uri);
            
            // If state was provided, store it too
            if (state != null && !state.isEmpty()) {
                session.setAttribute("oauth_state", state);
                logger.debug("Stored OAuth state: {}", state);
            }
        } else {
            logger.warn("No redirect_uri provided, using default");
            session.setAttribute("redirect_uri", defaultRedirectUrl);
            session.setAttribute("redirect_after_auth", defaultRedirectUrl);
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
    
    // Add this method to retrieve redirect URI from cache
    public static String getRedirectFromCache(HttpServletRequest request) {
        // Get the cache key from cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("redirect_cache_key".equals(cookie.getName())) {
                    String cacheKey = cookie.getValue();
                    Map<String, String> clientCache = REDIRECT_CACHE.get(cacheKey);
                    if (clientCache != null) {
                        String redirectUri = clientCache.get("redirect_uri");
                        if (redirectUri != null) {
                            return redirectUri;
                        }
                    }
                    break;
                }
            }
        }
        
        return null;
    }
    
    // Add method to get state from cache
    public static String getStateFromCache(HttpServletRequest request) {
        // Get the cache key from cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("redirect_cache_key".equals(cookie.getName())) {
                    String cacheKey = cookie.getValue();
                    Map<String, String> clientCache = REDIRECT_CACHE.get(cacheKey);
                    if (clientCache != null) {
                        return clientCache.get("oauth_state");
                    }
                    break;
                }
            }
        }
        
        return null;
    }
}