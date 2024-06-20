package com.example.service;

import com.example.model.DPoPToken;
import com.example.security.dpop.DPoPAuthorizedClient;
import com.example.security.dpop.DPoPClientCredentialsOAuth2AuthorizedClientProvider;
import com.example.security.dpop.DPoPProofBuilder;
import com.example.security.dpop.client.DPoPAccessTokenResponseClient;
import com.example.security.dpop.request.DPoPClientCredentialsGrantRequest;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;

@Slf4j
public class HelseIDDPoPClientCredentialTokenService {

  private final Clock clock = Clock.systemUTC();
  private final Duration clockSkew;
  private final ClientRegistration clientRegistration;
  private final DPoPProofBuilder dPoPProofBuilder;
  private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

  private final DPoPClientCredentialsOAuth2AuthorizedClientProvider
      dPoPClientCredentialsOAuth2AuthorizedClientProvider;

  public HelseIDDPoPClientCredentialTokenService(
      ClientRegistration clientRegistration,
      DPoPProofBuilder dPoPProofBuilder,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      DPoPAccessTokenResponseClient<DPoPClientCredentialsGrantRequest> credentialsGrantClient,
      Duration refreshTokenBeforeSeconds) {
    this.clientRegistration = clientRegistration;
    this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;

    dPoPClientCredentialsOAuth2AuthorizedClientProvider =
        new DPoPClientCredentialsOAuth2AuthorizedClientProvider(credentialsGrantClient);

    this.clockSkew =
        refreshTokenBeforeSeconds != null ? refreshTokenBeforeSeconds : Duration.ofSeconds(60);
    this.dPoPProofBuilder = dPoPProofBuilder;
  }

  public DPoPToken getAccessToken(String requestUrl, String requestMethod) {
    ClientRegistration clientRegistration = this.clientRegistration;

    OAuth2AuthorizedClient authorizedClient =
        oAuth2AuthorizedClientService.loadAuthorizedClient(
            clientRegistration.getRegistrationId(), clientRegistration.getClientName());

    if (authorizedClient == null || hasTokenExpired(authorizedClient.getAccessToken(), clockSkew)
        || !(authorizedClient instanceof DPoPAuthorizedClient)) {
      authorizedClient = authorizeNewClient(clientRegistration);
    }

    if (authorizedClient instanceof DPoPAuthorizedClient dPoPAuthorizedClient) {

      String tokenType = dPoPAuthorizedClient.getdPoPAccessToken().getTokenType().getValue();
      String tokenValue = dPoPAuthorizedClient.getdPoPAccessToken().getTokenValue();
      Set<String> scopes = dPoPAuthorizedClient.getdPoPAccessToken().getScopes();

      try {
        byte[] digest =
            MessageDigest.getInstance("SHA-256")
                .digest(tokenValue.getBytes(StandardCharsets.US_ASCII));
        String ath = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

        String dPoPHeader =
            dPoPProofBuilder.createDPoPProof(
                requestMethod,
                requestUrl,
                null,
                ath,
                clientRegistration);

        return new DPoPToken(tokenType, tokenValue, scopes, dPoPHeader);
      } catch (Exception e) {
        log.error(e.getMessage(), e);
      }
    }
    return null;
  }

  private OAuth2AuthorizedClient authorizeNewClient(ClientRegistration clientRegistration) {
    Authentication authentication = new HelseIDAuthentication(clientRegistration.getClientName());
    OAuth2AuthorizationContext context =
        OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
            .principal(authentication)
            .build();
    OAuth2AuthorizedClient authorizedClient =
        dPoPClientCredentialsOAuth2AuthorizedClientProvider.authorize(context);
    oAuth2AuthorizedClientService.saveAuthorizedClient(authorizedClient, authentication);
    return authorizedClient;
  }

  private boolean hasTokenExpired(AbstractOAuth2Token token, Duration clockSkew) {
    return token.getExpiresAt() != null
           && this.clock.instant().isAfter(token.getExpiresAt().minus(clockSkew));
  }

  private static final class HelseIDAuthentication extends AbstractAuthenticationToken {

    private final String principalName;

    public HelseIDAuthentication(String principalName) {
      super(new ArrayList<>());
      this.principalName = principalName;
    }

    @Override
    public Object getCredentials() {
      return null;
    }

    @Override
    public Object getPrincipal() {
      return principalName;
    }
  }
}
