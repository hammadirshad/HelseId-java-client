package com.example.security.dpop;

import com.example.security.dpop.client.DPoPAccessTokenResponseClient;
import com.example.security.dpop.request.DPoPClientCredentialsGrantRequest;
import com.example.security.dpop.response.DPoPAccessTokenResponse;
import java.time.Clock;
import java.time.Duration;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.util.Assert;

public class DPoPClientCredentialsOAuth2AuthorizedClientProvider
    implements OAuth2AuthorizedClientProvider {

  private final DPoPAccessTokenResponseClient<DPoPClientCredentialsGrantRequest>
      accessTokenResponseClient;

  private Duration clockSkew = Duration.ofSeconds(60);

  private Clock clock = Clock.systemUTC();

  public DPoPClientCredentialsOAuth2AuthorizedClientProvider(
      DPoPAccessTokenResponseClient<DPoPClientCredentialsGrantRequest> accessTokenResponseClient) {
    this.accessTokenResponseClient = accessTokenResponseClient;
  }

  @Override
  @Nullable
  public OAuth2AuthorizedClient authorize(OAuth2AuthorizationContext context) {
    Assert.notNull(context, "context cannot be null");
    ClientRegistration clientRegistration = context.getClientRegistration();
    if (!AuthorizationGrantType.CLIENT_CREDENTIALS.equals(
        clientRegistration.getAuthorizationGrantType())) {
      return null;
    }
    OAuth2AuthorizedClient authorizedClient = context.getAuthorizedClient();
    if (authorizedClient != null && !hasTokenExpired(authorizedClient.getAccessToken())) {

      return null;
    }

    DPoPClientCredentialsGrantRequest clientCredentialsGrantRequest =
        new DPoPClientCredentialsGrantRequest(clientRegistration);
    try {
      DPoPAccessTokenResponse tokenResponse =
          this.accessTokenResponseClient.getTokenResponse(clientCredentialsGrantRequest);
      return new DPoPAuthorizedClient(
          clientRegistration,
          context.getPrincipal().getName(),
          tokenResponse.getDPoPOAccessToken(),
          tokenResponse.getAdditionalParameters());
    } catch (OAuth2AuthorizationException ex) {
      throw new ClientAuthorizationException(
          ex.getError(), clientRegistration.getRegistrationId(), ex);
    }
  }

  private boolean hasTokenExpired(OAuth2Token token) {
    return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
  }

  public void setClockSkew(Duration clockSkew) {
    Assert.notNull(clockSkew, "clockSkew cannot be null");
    Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
    this.clockSkew = clockSkew;
  }

  public void setClock(Clock clock) {
    Assert.notNull(clock, "clock cannot be null");
    this.clock = clock;
  }
}
