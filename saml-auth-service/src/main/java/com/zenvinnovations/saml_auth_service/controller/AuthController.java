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
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.view.RedirectView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;
import java.util.Collections;
import java.util.stream.Collectors;

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
        // Generate JWT token
        String token = jwtService.generateJwtToken(authentication);
        
        logger.info("Generated token for user: {}", authentication.getName());
        
        // Log successful authentication
        auditService.logSuccessfulAuthentication("kong", authentication.getName());
        
        // Build final URL - always redirect to Kong with the token
        String redirectUrl = defaultRedirectUrl;
        if (!redirectUrl.contains("?")) {
            redirectUrl += "?token=" + token;
        } else {
            redirectUrl += "&token=" + token;
        }
        
        // For security, log the URL without the token
        String logUrl = redirectUrl.replaceAll("token=.*?(&|$)", "token=REDACTED$1");
        logger.info("Redirecting to: {}", logUrl);
        
        return new RedirectView(redirectUrl);
    }

    @RequestMapping(value = "/custom-logout", method = {RequestMethod.POST, RequestMethod.GET})
    public RedirectView logout(HttpServletRequest request) {
        logger.info("======= LOGOUT REQUEST RECEIVED =======");
        logger.info("Request URL: {}", request.getRequestURL());
        logger.info("Query string: {}", request.getQueryString());
        logger.info("Headers: {}", Collections.list(request.getHeaderNames()).stream()
            .collect(Collectors.toMap(h -> h, request::getHeader)));

        HttpSession session = request.getSession(false);
        if (session != null) {
            try {
                session.invalidate();
                logger.info("Session invalidated successfully");
            } catch (Exception e) {
                logger.error("Error invalidating session", e);
            }
        } else {
            logger.info("No session found to invalidate");
        }

        // Redirect to Kong-specific endpoint to clear cookies
        String redirectTo = request.getParameter("redirect_to");
        if (redirectTo == null || redirectTo.isEmpty()) {
            redirectTo = defaultRedirectUrl;
            logger.info("Using default redirect URL: {}", redirectTo);
        } else {
            logger.info("Using provided redirect URL: {}", redirectTo);
        }

        // Use ABSOLUTE URL to Kong's cookie clearing endpoint
        String targetUrl = "http://localhost:8000/kong-clear-cookies?redirect_to=" + redirectTo;
        logger.info("Redirecting to: {}", targetUrl);
        
        return new RedirectView(targetUrl);
    }
    
    @GetMapping("/login/error")
    public RedirectView handleLoginError(HttpServletRequest request) {
        logger.error("SAML authentication failed, redirecting to home page");
        return new RedirectView("http://localhost:3000?error=auth_failed");
    }
}