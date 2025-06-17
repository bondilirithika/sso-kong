//Users\Rithika\OneDrive\Desktop\saml-auth-service\src\main\java\com\zenvinnovations\saml_auth_service\controller\AuthController.java
package com.zenvinnovations.saml_auth_service.controller;

import com.zenvinnovations.saml_auth_service.service.AuditService;
import com.zenvinnovations.saml_auth_service.service.JwtService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.Map;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
public class AuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private AuditService auditService;

    @Value("${auth.default-redirect-url}")
    private String defaultRedirectUrl;
    
    @GetMapping("/token")
    public RedirectView getTokenAndRedirect(Authentication authentication, 
                                          HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        
        // Fallback URL to the Kong API gateway
        String redirectUrl = defaultRedirectUrl; 
        String state = null;
        
        if (session != null) {
            String sessionRedirect = (String) session.getAttribute("redirect_after_auth");
            if (sessionRedirect != null) {
                redirectUrl = sessionRedirect;
                logger.info("Using redirect URL from session: {}", redirectUrl);
            } else {
                logger.warn("No redirect_after_auth in session, using fallback URL: {}", redirectUrl);
            }
            
            // Get state if it was provided
            state = (String) session.getAttribute("oauth_state");
        } else {
            logger.warn("No session found, using fallback URL: {}", redirectUrl);
        }
        
        // Generate JWT
        String token = jwtService.generateJwtToken(authentication);
        
        logger.info("Generated token for user: {}", authentication.getName());
        
        // Build final URL
        StringBuilder finalUrl = new StringBuilder(redirectUrl);
        if (redirectUrl.contains("?")) {
            finalUrl.append("&token=").append(token);
        } else {
            finalUrl.append("?token=").append(token);
        }
        
        // Add state if it was provided
        if (state != null && !state.isEmpty()) {
            finalUrl.append("&state=").append(state);
        }

        // Log successful authentication
        auditService.logSuccessfulAuthentication("kong", authentication.getName());
        
        String logUrl = finalUrl.toString().replaceAll("token=.*?(&|$)", "token=REDACTED$1");
        logger.info("Redirecting to: {}", logUrl);
        return new RedirectView(finalUrl.toString());
    }

    @RequestMapping(value = "/logout", method = {RequestMethod.POST, RequestMethod.GET})
    public ResponseEntity<?> logout(
            @RequestParam(required = false) String forwarded,
            @RequestParam(required = false) String redirect_to,
            HttpServletRequest request,
            HttpServletResponse response) {
        
        logger.info("Logout request received, forwarded={}, redirect_to={}", forwarded, redirect_to);
        
        // Invalidate session
        HttpSession session = request.getSession(false);
        if (session != null) {
            logger.info("Invalidating session: {}", session.getId());
            try {
                // Log session attributes before invalidating
                Enumeration<String> attributeNames = session.getAttributeNames();
                while (attributeNames.hasMoreElements()) {
                    String name = attributeNames.nextElement();
                    logger.info("Session attribute before invalidation: {} = {}", name, session.getAttribute(name));
                }
                session.invalidate();
                logger.info("Session invalidated successfully");
            } catch (Exception e) {
                logger.error("Error invalidating session", e);
            }
        } else {
            logger.info("No session to invalidate");
        }

        // Clear all cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                logger.info("Found cookie: {}", cookie.getName());
                if (cookie.getName().contains("redirect") || 
                    cookie.getName().contains("auth") || 
                    cookie.getName().contains("return") ||
                    cookie.getName().equals("JSESSIONID") ||
                    cookie.getName().equals("access_token")) {
                    
                    Cookie newCookie = new Cookie(cookie.getName(), "");
                    newCookie.setMaxAge(0);
                    newCookie.setPath("/");
                    response.addCookie(newCookie);
                    logger.info("Cleared cookie: {}", cookie.getName());
                }
            }
        } else {
            logger.info("No cookies found to clear");
        }

        // IMPORTANT: Always return a 200 OK response with JSON, never a 302 redirect
        // Kong will handle the actual redirect
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("message", "Logout successful");
        responseBody.put("status", "session_invalidated");
        
        // Still include the redirect_to for Kong's reference
        String finalRedirect = redirect_to != null ? redirect_to : "http://localhost:8000/";
        if (finalRedirect.contains("ngrok")) {
            finalRedirect = "http://localhost:8000/";
        }
        responseBody.put("redirect_to", finalRedirect);
        
        logger.info("Returning JSON response with redirect_to: {}", finalRedirect);
        return ResponseEntity.ok(responseBody);
    }
    
    @GetMapping("/login/error")
    public RedirectView handleLoginError(HttpServletRequest request) {
        logger.error("SAML authentication failed, redirecting to home page");
        return new RedirectView("http://localhost:3000?error=auth_failed");
    }
}