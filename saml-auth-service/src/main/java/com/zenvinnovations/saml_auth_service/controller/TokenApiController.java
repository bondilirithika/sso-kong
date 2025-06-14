package com.zenvinnovations.saml_auth_service.controller;

import com.zenvinnovations.saml_auth_service.service.JwtService;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.Cookie;

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
    public ResponseEntity<?> getUserInfo(HttpServletRequest request) {
        try {
            // Get JWT token from cookie directly
            Cookie[] cookies = request.getCookies();
            String token = null;
            
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("access_token".equals(cookie.getName())) {
                        token = cookie.getValue();
                        break;
                    }
                }
            }
            
            // If token was found in cookies, validate it
            if (token != null) {
                try {
                    Claims claims = jwtService.validateToken(token);
                    
                    Map<String, Object> userInfo = new HashMap<>();
                    userInfo.put("sub", claims.getSubject());
                    userInfo.put("email", claims.get("email", String.class));
                    userInfo.put("name", claims.get("name", String.class)); 
                    userInfo.put("authenticated", true);
                    
                    return ResponseEntity.ok(userInfo);
                } catch (Exception e) {
                    logger.error("Token validation failed: {}", e.getMessage());
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid token"));
                }
            }
            
            // No token found, user is not authenticated
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Not authenticated"));
        } catch (Exception e) {
            logger.error("Error processing userinfo request", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Internal server error"));
        }
    }
}