package com.example.service;

import com.example.config.OAuth2ClientDetailProperties;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;

@Slf4j
public class AuthorizationDetailsJwtClientParametersConverter<T extends AbstractOAuth2AuthorizationGrantRequest> implements
    Converter<T, MultiValueMap<String, String>> {

  private final JwtClientAssertionParametersService jwtClientAssertionParametersService;

  public AuthorizationDetailsJwtClientParametersConverter(
      Map<String, OAuth2ClientDetailProperties.Registration> registrations) {
    this.jwtClientAssertionParametersService = new JwtClientAssertionParametersService(registrations);
  }

  @Override
  public MultiValueMap<String, String> convert(T authorizationGrantRequest) {
    Assert.notNull(authorizationGrantRequest, "authorizationGrantRequest cannot be null");

    ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
    if (!ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(
        clientRegistration.getClientAuthenticationMethod())
        && !ClientAuthenticationMethod.CLIENT_SECRET_JWT
        .equals(clientRegistration.getClientAuthenticationMethod())) {
      return null;
    }

    return jwtClientAssertionParametersService.buildClientAssertionParameters(
        clientRegistration);
  }


}

