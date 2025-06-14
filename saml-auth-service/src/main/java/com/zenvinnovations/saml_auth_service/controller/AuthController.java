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
import org.springframework.web.servlet.view.RedirectView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.Map;

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

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // For a complete logout, provide the Google logout URL
        // But let Kong handle the cookie and redirect
        String googleLogoutUrl = "https://accounts.google.com/logout";
        
        return ResponseEntity.ok(Map.of(
            "message", "Logout successful",
            "idpLogoutUrl", googleLogoutUrl
        ));
    }
    
    @GetMapping("/login/error")
    public RedirectView handleLoginError(HttpServletRequest request) {
        logger.error("SAML authentication failed, redirecting to home page");
        return new RedirectView("http://localhost:3000?error=auth_failed");
    }
}