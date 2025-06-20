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
        
        // Just store state if needed, but rely on Kong for redirect
        HttpSession session = request.getSession(true);
        if (state != null && !state.isEmpty()) {
            session.setAttribute("oauth_state", state);
        }
        
        // Proceed to SAML authentication
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