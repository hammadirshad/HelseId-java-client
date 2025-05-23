package com.example.service;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;

public class HelseIDClientCredentialTokenService {

  private final Clock clock = Clock.systemUTC();
  private final Duration clockSkew = Duration.ofSeconds(60);
  private final ClientRegistration clientRegistration;
  private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

  private final ClientCredentialsOAuth2AuthorizedClientProvider
      clientCredentialsAuthorizedClientProvider;

  public HelseIDClientCredentialTokenService(
      ClientRegistration clientRegistration,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      ClientCredentialsOAuth2AuthorizedClientProvider authorizedClientProvider) {
    this.clientRegistration = clientRegistration;
    this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
    this.clientCredentialsAuthorizedClientProvider = authorizedClientProvider;
  }

  public OAuth2AccessToken getAccessToken() {
    return getAccessToken(this.clockSkew);
  }

  public OAuth2AccessToken getAccessToken(Duration clockSkew) {

    OAuth2AuthorizedClient authorizedClient =
        oAuth2AuthorizedClientService.loadAuthorizedClient(
            clientRegistration.getRegistrationId(), clientRegistration.getClientName());

    if (authorizedClient == null
        || hasTokenExpired(authorizedClient.getAccessToken(), clockSkew)
        || authorizedClient.getAccessToken().getTokenType() != TokenType.BEARER) {

      authorizedClient = authorizeNewClient(clientRegistration);
    }
    return authorizedClient != null ? authorizedClient.getAccessToken() : null;
  }

  private boolean hasTokenExpired(AbstractOAuth2Token token, Duration clockSkew) {
    return token.getExpiresAt() != null
        && this.clock.instant().isAfter(token.getExpiresAt().minus(clockSkew));
  }

  private OAuth2AuthorizedClient authorizeNewClient(ClientRegistration clientRegistration) {
    Authentication authentication = new HelseIDAuthentication(clientRegistration.getClientName());
    OAuth2AuthorizationContext context =
        OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
            .principal(authentication)
            .build();
    OAuth2AuthorizedClient authorizedClient =
        clientCredentialsAuthorizedClientProvider.authorize(context);
    oAuth2AuthorizedClientService.saveAuthorizedClient(authorizedClient, authentication);
    return authorizedClient;
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
