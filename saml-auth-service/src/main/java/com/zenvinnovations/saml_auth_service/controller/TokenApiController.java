package com.zenvinnovations.saml_auth_service.controller;

import com.zenvinnovations.saml_auth_service.service.JwtService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

@RestController
@RequestMapping("/api")
public class TokenApiController {

    private static final Logger logger = LoggerFactory.getLogger(TokenApiController.class);

    @Autowired
    private JwtService jwtService;
    
    @GetMapping("/token/validate")
    public ResponseEntity<?> validateToken(@RequestParam String token) {
        logger.debug("Token validation request received");
        
        try {
            Claims claims = jwtService.validateToken(token);
            String username = claims.getSubject();
            
            logger.info("Token validated successfully for user: {}", username);
            
            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("username", username);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.warn("Token validation failed: {}", e.getMessage());
            
            Map<String, Object> response = new HashMap<>();
            response.put("valid", false);
            response.put("error", "Invalid token");
            
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }
    
    @GetMapping("/userinfo")
    public ResponseEntity<?> getUserInfo(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            logger.warn("Unauthenticated request to /api/userinfo");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("authenticated", false));
        }
        
        logger.info("User info requested for: {}", authentication.getName());
        
        // Extract the principal as a Saml2AuthenticatedPrincipal if available
        Object principal = authentication.getPrincipal();
        Map<String, Object> userInfo = new HashMap<>();
        
        if (principal instanceof Saml2AuthenticatedPrincipal) {
            Saml2AuthenticatedPrincipal samlPrincipal = (Saml2AuthenticatedPrincipal) principal;
            
            // Add all available attributes from SAML response
            userInfo.put("email", authentication.getName());
            userInfo.put("sub", authentication.getName());
            userInfo.put("name", samlPrincipal.getFirstAttribute("name"));
            
            // Add any other SAML attributes
            for (String attrName : samlPrincipal.getAttributes().keySet()) {
                if (!userInfo.containsKey(attrName)) {
                    userInfo.put(attrName, samlPrincipal.getFirstAttribute(attrName));
                }
            }
        } else {
            // Fallback if not a SAML principal
            userInfo.put("email", authentication.getName());
            userInfo.put("sub", authentication.getName());
        }
        
        // Add authentication info
        userInfo.put("authenticated", true);
        
        // Add roles/authorities if available
        if (authentication.getAuthorities() != null) {
            List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
            userInfo.put("roles", authorities);
        }
        
        return ResponseEntity.ok(userInfo);
    }
}