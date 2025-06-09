package com.zenvinnovations.saml_auth_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret:defaultSecretKeyWhichShouldBeAtLeast32CharsLong}")
    private String jwtSecret;
    
    @Value("${jwt.expiration:86400000}") // 24 hours in milliseconds
    private long jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        // Extract user attributes from SAML assertion
        Map<String, Object> claims = new HashMap<>();
        
        if (authentication instanceof Saml2Authentication samlAuth) {
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) samlAuth.getPrincipal();
            
            // Get attributes from the SAML principal
            principal.getAttributes().forEach((key, values) -> {
                if (values != null && !values.isEmpty()) {
                    claims.put(key, values.get(0)); // Use first value
                }
            });
            
            // Add standard claims
            claims.put("sub", principal.getName());
            claims.put("email", principal.getName()); // Assuming email is the username
        } else {
            // Fallback for non-SAML authentication
            claims.put("sub", authentication.getName());
            claims.put("email", authentication.getName());
        }
        
        claims.put("iss", "shared-key"); // Must match Kong's config
        // Add timestamp claims
        claims.put("iat", new Date());
        claims.put("exp", new Date(System.currentTimeMillis() + jwtExpirationMs));
        
        return Jwts.builder()
                .setClaims(claims)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    private Key getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes();
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    public boolean validateJwtToken(String token) {
        try {
            Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    // Add this method to provide the validateToken functionality that your controller needs
    public Claims validateToken(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (Exception e) {
            throw new RuntimeException("Invalid JWT token: " + e.getMessage());
        }
    }

    public Map<String, Object> getClaimsFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (Exception e) {
            return Map.of();
        }
    }
}