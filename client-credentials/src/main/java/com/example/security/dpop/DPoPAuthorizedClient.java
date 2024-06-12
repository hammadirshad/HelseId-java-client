package com.example.security.dpop;

import com.example.security.dpop.response.DPoPAccessToken;
import java.util.Map;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;

public class DPoPAuthorizedClient extends OAuth2AuthorizedClient {

  private final DPoPAccessToken dPoPAccessToken;
  private final Map<String, Object> additionalParameters;

  public DPoPAuthorizedClient(
      ClientRegistration clientRegistration,
      String principalName,
      DPoPAccessToken dPoPAccessToken,
      Map<String, Object> additionalParameters) {
    super(
        clientRegistration,
        principalName,
        new OAuth2AccessToken(
            TokenType.BEARER,
            dPoPAccessToken.getTokenValue(),
            dPoPAccessToken.getIssuedAt(),
            dPoPAccessToken.getExpiresAt(),
            dPoPAccessToken.getScopes()));
    this.dPoPAccessToken = dPoPAccessToken;
    this.additionalParameters = additionalParameters;
  }

  public DPoPAccessToken getdPoPAccessToken() {
    return dPoPAccessToken;
  }

  public Map<String, Object> getAdditionalParameters() {
    return additionalParameters;
  }
}
