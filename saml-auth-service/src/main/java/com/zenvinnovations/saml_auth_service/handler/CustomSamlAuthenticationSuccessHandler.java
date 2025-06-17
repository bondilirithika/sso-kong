package com.zenvinnovations.saml_auth_service.handler;

import com.zenvinnovations.saml_auth_service.service.JwtService;
import com.zenvinnovations.saml_auth_service.service.AuditService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;
import jakarta.servlet.http.Cookie;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.zenvinnovations.saml_auth_service.controller.EnterpriseAuthController;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Component
public class CustomSamlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomSamlAuthenticationSuccessHandler.class);
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private AuditService auditService;
    
    @Value("${auth.default-redirect-url:http://localhost:8000}")
    private String defaultRedirectUrl;
    
    private String findRedirectUrl(HttpServletRequest request) {
        // Default fallback
        String redirectUrl = defaultRedirectUrl;
        logger.debug("Starting redirect URL lookup...");
        
        // First check session
        HttpSession session = request.getSession(false);
        if (session != null) {
            logger.debug("Checking session: {}", session.getId());
            String sessionRedirect = (String) session.getAttribute("redirect_uri");
            if (sessionRedirect != null && !sessionRedirect.isEmpty()) {
                logger.info("Found redirect URL in session (redirect_uri): {}", sessionRedirect);
                return sessionRedirect;
            }
            
            sessionRedirect = (String) session.getAttribute("redirect_after_auth");
            if (sessionRedirect != null && !sessionRedirect.isEmpty()) {
                logger.info("Found redirect URL in session (redirect_after_auth): {}", sessionRedirect);
                return sessionRedirect;
            }
        } else {
            logger.debug("No active session found for redirect lookup");
        }
        
        // Then check cookies as fallback
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            logger.debug("Checking {} cookies", cookies.length);
            for (Cookie cookie : cookies) {
                logger.debug("Examining cookie: {}", cookie.getName());
                if ("auth_redirect_uri".equals(cookie.getName()) || 
                    "redirect_uri".equals(cookie.getName()) || 
                    "return_after_auth".equals(cookie.getName())) {
                    
                    try {
                        // If base64 encoded
                        String value = cookie.getValue();
                        logger.info("Found redirect URL in cookie {}: {}", cookie.getName(), value);
                        try {
                            byte[] decodedBytes = Base64.getDecoder().decode(value);
                            String decodedUri = new String(decodedBytes);
                            logger.info("Successfully decoded redirect URL: {}", decodedUri);
                            
                            // Fix for http://localhost/ vs http://localhost:8000/
                            if (decodedUri.startsWith("http://localhost/")) {
                                decodedUri = decodedUri.replace("http://localhost/", "http://localhost:8000/");
                                logger.info("Fixed URL to use correct port: {}", decodedUri);
                            }
                            
                            return decodedUri;
                        } catch (IllegalArgumentException e) {
                            // Not base64, use as-is
                            logger.info("Using non-base64 cookie value as is: {}", value);
                            return value;
                        }
                    } catch (Exception e) {
                        logger.error("Error processing redirect cookie {}: {}", cookie.getName(), e.getMessage());
                    }
                }
            }
        } else {
            logger.debug("No cookies found for redirect lookup");
        }
        
        logger.info("No redirect URL found, using default: {}", redirectUrl);
        return redirectUrl;
    }
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, 
                                      Authentication authentication) throws IOException {
        logger.info("SAML authentication successful for user: {}", authentication.getName());
        
        // Default redirect URL
        String redirectUrl = findRedirectUrl(request);
        
        // 1. FIRST: Log ALL request details for debugging
        logger.debug("Authentication success handler details:");
        logger.debug("  Session ID: {}", request.getSession(false) != null ? request.getSession(false).getId() : "none");
        logger.debug("  Request URI: {}", request.getRequestURI());
        logger.debug("  Remote Host: {}", request.getRemoteHost());
        
        // 2. SECOND: Check all headers and cookies
        logger.debug("Request headers:");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            logger.debug("  {}: {}", headerName, request.getHeader(headerName));
        }
        
        // 3. Check cookies with improved logging
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            logger.debug("Found {} cookies:", cookies.length);
            for (Cookie cookie : cookies) {
                logger.debug("Cookie: {} = {}", cookie.getName(), cookie.getValue());
                
                // Look for our redirect cookies with ANY name that might contain it
                if (cookie.getName().contains("redirect") || 
                    cookie.getName().contains("return") || 
                    cookie.getName().contains("auth")) {
                    
                    try {
                        String encodedUrl = cookie.getValue();
                        if (encodedUrl != null && !encodedUrl.isEmpty()) {
                            logger.debug("Attempting to decode cookie: {}", cookie.getName());
                            byte[] decodedBytes = Base64.getDecoder().decode(encodedUrl);
                            String cookieRedirect = new String(decodedBytes);
                            logger.info("Successfully decoded cookie value: {}", cookieRedirect);
                            
                            // Fix the URL with a more robust approach
                            if (cookieRedirect.startsWith("http://localhost/")) {
                                String pathPart = cookieRedirect.substring("http://localhost/".length());
                                cookieRedirect = "http://localhost:8000/" + pathPart;
                                logger.info("Fixed cookie redirect URL to use correct port: {}", cookieRedirect);
                            }
                            
                            redirectUrl = cookieRedirect;
                            logger.info("Using redirect URL from cookie {}: {}", cookie.getName(), redirectUrl);
                            
                            // Break after finding a valid cookie
                            break;
                        }
                    } catch (Exception e) {
                        logger.error("Error decoding cookie {}: {}", cookie.getName(), e.getMessage());
                    }
                }
            }
        } else {
            logger.warn("No cookies found in the request!");
        }
        
        // 4. Fallback to session if no cookies found
        if (redirectUrl.equals(defaultRedirectUrl)) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                logger.debug("Checking session attributes in ID: {}", session.getId());
                Enumeration<String> attributeNames = session.getAttributeNames();
                while (attributeNames.hasMoreElements()) {
                    String name = attributeNames.nextElement();
                    Object value = session.getAttribute(name);
                    logger.debug("  - {}: {}", name, value);
                    
                    // Check for any attribute that might contain a redirect URL
                    if ((name.contains("redirect") || name.contains("return")) && 
                        value instanceof String && 
                        ((String)value).startsWith("http")) {
                        
                        redirectUrl = (String)value;
                        logger.info("Using redirect URL from session attribute {}: {}", name, redirectUrl);
                        break;
                    }
                }
                
                // Clean up session attributes
                session.removeAttribute("redirect_uri");
                session.removeAttribute("redirect_after_auth");
            }
        }
        
        // Generate JWT token
        String token = jwtService.generateJwtToken(authentication);
        logger.info("Generated JWT token for user: {}", authentication.getName());
        
        // Add cookie with the token for Kong to use
        Cookie tokenCookie = new Cookie("access_token", token);
        tokenCookie.setPath("/");
        tokenCookie.setHttpOnly(true);
        tokenCookie.setMaxAge(86400); // 1 day
        response.addCookie(tokenCookie);
        
        // Log successful authentication
        auditService.logSuccessfulAuthentication("kong", authentication.getName());
        
        // Build final URL with token
        StringBuilder finalUrl = new StringBuilder();
        if (redirectUrl.contains("?")) {
            finalUrl.append(redirectUrl).append("&token=").append(token);
        } else {
            finalUrl.append(redirectUrl).append("?token=").append(token);
        }
        
        String logUrl = finalUrl.toString().replaceAll("token=.*?(&|$)", "token=REDACTED$1");
        logger.info("Redirecting to: {}", logUrl);
        
        // Set a more specific response header to ensure proper redirect
        response.setHeader("Cache-Control", "no-store");
        
        // Redirect to final URL with token
        response.sendRedirect(finalUrl.toString());
    }
}