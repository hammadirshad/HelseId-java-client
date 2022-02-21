package com.example.config;

import com.example.filter.ExpiredTokenFilter;
import com.example.security.OidcHelseIDBrukerService;
import com.example.service.HelseIDJwtAuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

@Configuration
public class OAuth2Configuration {
    private final ClientRegistration clientRegistration;

    public OAuth2Configuration(
            OAuth2ClientHelseIDProperties helseIDProperties,
            ClientRegistrationRepository clientRegistrationRepository) {
        clientRegistration =
                clientRegistrationRepository.findByRegistrationId(
                        helseIDProperties.getRegistrationName().getLogin());
    }

    @Bean
    public ExpiredTokenFilter expiredTokenFilter(OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
        return new ExpiredTokenFilter(oAuth2AuthorizedClientRepository, oidcHelseIDBrukerService());
    }

    @Bean
    public OidcHelseIDBrukerService oidcHelseIDBrukerService() {
        return new OidcHelseIDBrukerService(clientRegistration);
    }

    @Bean
    public HelseIDJwtAuthenticationConverter jwtAuthenticationConverter(
            OidcHelseIDBrukerService oidcHelseIDBrukerService) {
        return new HelseIDJwtAuthenticationConverter(clientRegistration, oidcHelseIDBrukerService);
    }

}
