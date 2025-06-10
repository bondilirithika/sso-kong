package com.zenvinnovations.saml_auth_service.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
@EnableWebSecurity
public class SamlSecurityConfig {
    
    private static final Logger logger = LoggerFactory.getLogger(SamlSecurityConfig.class);
    
    @Value("${saml.entity-id}")
    private String entityId;
    
    @Value("${saml.acs-url}")
    private String acsUrl;
    
    @Value("${saml.idp-entity-id}")
    private String idpEntityId;
    
    @Value("${saml.idp-sso-url}")
    private String idpSsoUrl;
    
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private long jwtExpiration;
    
    @Value("${auth.default-redirect-url}")
    private String defaultRedirectUrl;
    
    @Autowired
    private OpenSaml4AuthenticationProvider samlAuthenticationProvider;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/saml/**", "/api/token/validate", "/api/userinfo", "/auth", "/error", "/logout", "/token", "/login/error").permitAll()
                .anyRequest().authenticated()
            )
            .saml2Login(saml2 -> saml2
                .loginPage("/auth") // This is important! Prevents default login page
                .defaultSuccessUrl("/token", true)
                .successHandler(samlAuthenticationSuccessHandler())
                .authenticationManager(samlAuthenticationProvider::authenticate)
                .loginProcessingUrl("/login/saml2/sso/google-workspace")
            )
            .logout(logout -> logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
            )
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/**", "/auth", "/token", "/logout")
            )
            .headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.deny())
            );
        
        return http.build();
    }
    
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {
        Saml2X509Credential verificationCredential = getGoogleCertificateFromMetadata();
        
        // Create a basic RelyingPartyRegistration
        RelyingPartyRegistration registration = RelyingPartyRegistration
            .withRegistrationId("google-workspace")
            .entityId(entityId)
            .assertionConsumerServiceLocation(acsUrl)
            .assertingPartyDetails(party -> party
                .entityId(idpEntityId)
                .singleSignOnServiceLocation(idpSsoUrl)
                .wantAuthnRequestsSigned(false)
                .verificationX509Credentials(c -> c.add(verificationCredential))
            )
            .build();
        
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }
    
    private Saml2X509Credential getGoogleCertificateFromMetadata() throws Exception {
        try {
            // Extract certificate from metadata XML
            Resource metadataResource = new ClassPathResource("saml/GoogleIDPMetadata.xml");
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            
            Document doc = dbFactory.newDocumentBuilder().parse(metadataResource.getInputStream());
            doc.getDocumentElement().normalize();
            
            // Find X509Certificate element
            NodeList certList = doc.getElementsByTagName("ds:X509Certificate");
            
            if (certList.getLength() > 0) {
                // Get certificate content
                String certContent = certList.item(0).getTextContent();
                
                // Format certificate with header and footer
                String formattedCert = "-----BEGIN CERTIFICATE-----\n" + 
                                      certContent + 
                                      "\n-----END CERTIFICATE-----";
                
                // Parse the certificate
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(formattedCert.getBytes(StandardCharsets.UTF_8))
                );
                
                return Saml2X509Credential.verification(certificate);
            } else {
                throw new Exception("Certificate not found in metadata");
            }
        } catch (Exception e) {
            logger.error("Error parsing Google IDP metadata", e);
            throw new RuntimeException("Error parsing Google IDP metadata", e);
        }
    }
    
    @Bean
    public AuthenticationSuccessHandler samlAuthenticationSuccessHandler() {
        return (request, response, authentication) -> {
            logger.info("SAML authentication successful for user: {}", authentication.getName());
            
            // Generate JWT token directly here
            String token = generateJwtToken(authentication);
            logger.info("Generated JWT token for user: {}", authentication.getName());
            
            // Use default redirect URL
            String redirectUrl = defaultRedirectUrl;
            
            // FIX: Get redirect URL from session instead
            HttpSession session = request.getSession(false);
            if (session != null) {
                String sessionRedirect = (String) session.getAttribute("redirect_after_auth");
                if (sessionRedirect != null && !sessionRedirect.isEmpty()) {
                    redirectUrl = sessionRedirect;
                    logger.info("Using redirect URL from session: {}", redirectUrl);
                } else {
                    logger.warn("No redirect_after_auth in session, using fallback URL: {}", redirectUrl);
                }
            } else {
                logger.warn("No session found, using fallback URL: {}", redirectUrl);
            }
            
            // Build redirect URL with token
            StringBuilder finalUrl = new StringBuilder();
            if (redirectUrl.contains("?")) {
                finalUrl.append(redirectUrl).append("&token=").append(token);
            } else {
                finalUrl.append(redirectUrl).append("?token=").append(token);
            }
            
            String logUrl = finalUrl.toString().replaceAll("token=.*?(&|$)", "token=REDACTED$1");
            logger.info("Redirecting to: {}", logUrl);
            
            // Redirect to final URL with token
            response.sendRedirect(finalUrl.toString());
        };
    }
    
    private String generateJwtToken(Authentication authentication) {
        try {
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + jwtExpiration);
            
            return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .claim("email", authentication.getName())
                .claim("iss", "shared-key") // Must match Kong config
                .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                .compact();
        } catch (Exception e) {
            logger.error("Error generating JWT token", e);
            throw new RuntimeException("Error generating JWT token", e);
        }
    }
}
