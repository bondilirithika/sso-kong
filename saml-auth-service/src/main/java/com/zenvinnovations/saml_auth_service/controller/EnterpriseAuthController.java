package com.zenvinnovations.saml_auth_service.controller;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

@Controller
public class EnterpriseAuthController {
    
    private static final Logger logger = LoggerFactory.getLogger(EnterpriseAuthController.class);
    
    // This is only needed if you're checking redirect URIs directly, which Kong now handles
    // @Value("${auth.allowed-domains}")
    // private String allowedDomains;
    
    @Value("${auth.default-redirect-url}")
    private String defaultRedirectUrl;
    
        
    @GetMapping("/auth")
    public RedirectView initiateAuth(
            @RequestParam(required = false) String redirect_uri,
            @RequestParam(required = false) String state,
            HttpServletRequest request) {
        
        logger.info("Authentication request received");
        
        // Just store the state if provided - Kong handles redirect_uri in cookie
        HttpSession session = request.getSession(true);
        if (state != null && !state.isEmpty()) {
            session.setAttribute("oauth_state", state);
        }
        
        // Proceed to SAML authentication
        return new RedirectView("/saml2/authenticate/google-workspace");
    }
    
    // This method is not used since Kong handles redirect validation
    // private boolean isValidRedirectUri(String uri) {
    //    ...
    // }
}