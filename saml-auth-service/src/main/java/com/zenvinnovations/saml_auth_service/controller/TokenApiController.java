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
    public ResponseEntity<?> getUserInfo(
            @RequestHeader(value = "X-User-Email", required = false) String email,
            @RequestHeader(value = "X-User-Name", required = false) String name,
            @RequestHeader(value = "X-User-Sub", required = false) String sub) {

        if (email == null && sub == null) {
            logger.warn("Unauthenticated request to /api/userinfo (missing Kong headers)");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("authenticated", false));
        }

        logger.info("User info requested for: {}", email != null ? email : sub);

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("email", email);
        userInfo.put("sub", sub != null ? sub : email);
        userInfo.put("name", name != null ? name : email);
        userInfo.put("authenticated", true);

        return ResponseEntity.ok(userInfo);
    }
}