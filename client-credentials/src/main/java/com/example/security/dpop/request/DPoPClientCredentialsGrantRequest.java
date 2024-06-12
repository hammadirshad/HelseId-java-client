package com.example.security.dpop.request;

import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

public class DPoPClientCredentialsGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

  public DPoPClientCredentialsGrantRequest(ClientRegistration clientRegistration) {
    super(AuthorizationGrantType.CLIENT_CREDENTIALS, clientRegistration);
    Assert.isTrue(AuthorizationGrantType.CLIENT_CREDENTIALS.equals(
            clientRegistration.getAuthorizationGrantType()),
        "clientRegistration.authorizationGrantType must be AuthorizationGrantType.CLIENT_CREDENTIALS");
  }
}
