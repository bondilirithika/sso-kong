package com.zenvinnovations.saml_auth_service.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtService {
    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);

    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private long jwtExpiration;
    
    public String generateJwtToken(Authentication authentication) {
        // Get user details
        String username = authentication.getName();
        
        // Create JWT token with only necessary claims for Kong
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
            .claim("iss", "shared-key")  // MUST match the "key" field in Kong
            .claim("email", username)
            .claim("name", username)
            .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
            .compact();
    }
    
    public Claims validateToken(String token) {
        logger.info("Validating JWT token: {}", token);
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
            logger.info("JWT validated successfully. Claims: {}", claims);
            return claims;
        } catch (Exception e) {
            logger.error("JWT validation failed: {}", e.getMessage(), e);
            throw e;
        }
    }
}