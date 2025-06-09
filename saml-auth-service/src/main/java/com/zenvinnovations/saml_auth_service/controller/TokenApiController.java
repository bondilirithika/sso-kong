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
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Not authenticated"));
        }
        
        logger.info("User info requested for: {}", authentication.getName());
        
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("username", authentication.getName());
        userInfo.put("authenticated", true);
        
        // Add other user attributes if available
        if (authentication.getAuthorities() != null) {
            List<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
            userInfo.put("authorities", authorities);
        }
        
        return ResponseEntity.ok(userInfo);
    }
}