package com.example.config;

import com.example.service.HelseIDClientCredentialTokenService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@Slf4j
@Configuration
@EnableConfigurationProperties({
        OAuth2ClientHelseIDProperties.class,
})
@Conditional(ClientsConfiguredCondition.class)
public class HelseIDClientConfiguration {

    private final OAuth2ClientHelseIDProperties oAuth2ClientHelseIDProperties;
    private final ClientCredentialsOAuth2AuthorizedClientProvider
            clientCredentialsAuthorizedClientProvider;
    private final RefreshTokenOAuth2AuthorizedClientProvider refreshTokenauthorizedClientProvider;

    public HelseIDClientConfiguration(
            OAuth2ClientHelseIDProperties oAuth2ClientHelseIDProperties,
            OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
                    credentialsGrantResponseClient,
            OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
                    refreshTokenTokenResponseClient) {
        this.oAuth2ClientHelseIDProperties = oAuth2ClientHelseIDProperties;

        clientCredentialsAuthorizedClientProvider =
                new ClientCredentialsOAuth2AuthorizedClientProvider();
        clientCredentialsAuthorizedClientProvider.setAccessTokenResponseClient(
                credentialsGrantResponseClient);

        refreshTokenauthorizedClientProvider = new RefreshTokenOAuth2AuthorizedClientProvider();
        refreshTokenauthorizedClientProvider.setAccessTokenResponseClient(
                refreshTokenTokenResponseClient);
    }

    @ConditionalOnProperty(prefix = "helseid", value = "registration-name.machine")
    @Bean
    public HelseIDClientCredentialTokenService helseIDClientCredentialTokenService(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        String registrationName = oAuth2ClientHelseIDProperties.getRegistrationName().getMachine();
        ClientRegistration clientRegistration =
                clientRegistrationRepository.findByRegistrationId(registrationName);
        return new HelseIDClientCredentialTokenService(
                registrationName,
                clientRegistration,
                oAuth2AuthorizedClientService,
                clientCredentialsAuthorizedClientProvider,
                refreshTokenauthorizedClientProvider);
    }
}

