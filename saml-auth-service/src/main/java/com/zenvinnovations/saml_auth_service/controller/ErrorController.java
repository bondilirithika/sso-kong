package com.zenvinnovations.saml_auth_service.controller;

import com.zenvinnovations.saml_auth_service.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ErrorController {

    @Autowired
    private AuditService auditService;
    
    @GetMapping("/error")
    public String handleError(@RequestParam(required = false) String code, 
                            HttpServletRequest request,
                            Model model) {
        
        String message;
        switch (code != null ? code : "") {
            case "invalid_client":
                message = "Invalid client application";
                break;
            case "invalid_credentials":
                message = "Invalid credentials";
                break;
            case "inactive_client":
                message = "Client application is inactive";
                break;
            case "invalid_session":
                message = "Invalid or expired session";
                break;
            default:
                message = "An error occurred";
        }
        
        model.addAttribute("errorMessage", message);
        model.addAttribute("errorCode", code != null ? code : "unknown_error");
        
        // Log the error safely
        try {
            String clientId = (String) request.getSession().getAttribute("client_id");
            if (clientId != null) {
                auditService.logFailedAuthentication(clientId, code != null ? code : "unknown_error");
            }
        } catch (Exception e) {
            // Handle safely in case of session issues
        }
        
        return "error";
    }
}