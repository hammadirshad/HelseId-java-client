package com.example.service;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;

public class HelseIDClientCredentialTokenService {

    private final String registrationName;
    private final Clock clock = Clock.systemUTC();
    private final Duration clockSkew = Duration.ofSeconds(60);
    private final ClientRegistration clientRegistration;
    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    private final ClientCredentialsOAuth2AuthorizedClientProvider
            clientCredentialsAuthorizedClientProvider;
    private final RefreshTokenOAuth2AuthorizedClientProvider refreshTokenauthorizedClientProvider;

    public HelseIDClientCredentialTokenService(
            String registrationName,
            ClientRegistration clientRegistration,
            OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
            ClientCredentialsOAuth2AuthorizedClientProvider authorizedClientProvider,
            RefreshTokenOAuth2AuthorizedClientProvider refreshTokenauthorizedClientProvider) {
        this.registrationName = registrationName;
        this.clientRegistration = clientRegistration;
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
        this.clientCredentialsAuthorizedClientProvider = authorizedClientProvider;

        this.refreshTokenauthorizedClientProvider = refreshTokenauthorizedClientProvider;
    }

    public OAuth2AccessToken getAccessToken() {

        String clientName = clientRegistration.getClientName();
        Authentication authentication = new HelseIDAuthentication(clientName);

        OAuth2AuthorizationContext context =
                OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
                        .principal(authentication)
                        .build();

        OAuth2AuthorizedClient authorizedClient =
                oAuth2AuthorizedClientService.loadAuthorizedClient(registrationName, clientName);

        if (authorizedClient == null) {
            authorizedClient = clientCredentialsAuthorizedClientProvider.authorize(context);
            oAuth2AuthorizedClientService.saveAuthorizedClient(authorizedClient, authentication);
        } else if (hasTokenExpired(authorizedClient.getAccessToken())) {
            authorizedClient = refreshTokenauthorizedClientProvider.authorize(context);
            if (authorizedClient == null) {
                authorizedClient = clientCredentialsAuthorizedClientProvider.authorize(context);
            }
            oAuth2AuthorizedClientService.saveAuthorizedClient(authorizedClient, authentication);
        }

        return authorizedClient != null ? authorizedClient.getAccessToken() : null;
    }

    private boolean hasTokenExpired(AbstractOAuth2Token token) {
        return token.getExpiresAt() != null
                && this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
    }

    private static final class HelseIDAuthentication extends AbstractAuthenticationToken {

        private final String clientName;

        public HelseIDAuthentication(String clientName) {
            super(new ArrayList<>());
            this.clientName = clientName;
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public Object getPrincipal() {
            return clientName;
        }
    }
}

