package com.zenvinnovations.saml_auth_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
public class CustomSaml2ValidationConfiguration {
    
    private static final Logger logger = LoggerFactory.getLogger(CustomSaml2ValidationConfiguration.class);
    
    @Bean
    public OpenSaml4AuthenticationProvider saml2AuthenticationProvider() {
        OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
        
        // Replace the response authentication converter
        provider.setResponseAuthenticationConverter(responseToken -> {
            logger.info("Processing SAML response with custom validator");
            
            // Extract username from SAML response for logging
            if (responseToken.getResponse() != null && 
                responseToken.getResponse().getAssertions() != null && 
                !responseToken.getResponse().getAssertions().isEmpty() &&
                responseToken.getResponse().getAssertions().get(0).getSubject() != null &&
                responseToken.getResponse().getAssertions().get(0).getSubject().getNameID() != null) {
                
                String username = responseToken.getResponse().getAssertions().get(0).getSubject().getNameID().getValue();
                logger.info("Successfully extracted username from SAML response: {}", username);
            }
            
            // Use the default converter, which will extract attributes and create the authentication
            return OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);
        });
        
        return provider;
    }
}