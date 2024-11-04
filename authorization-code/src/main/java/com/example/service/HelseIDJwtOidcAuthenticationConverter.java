package com.example.service;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;

@Slf4j
public class HelseIDJwtOidcAuthenticationConverter
    implements Converter<Jwt, AbstractAuthenticationToken> {

  private static final String EXPIRES_AT = "exp";
  private static final String ISSUED_AT = "iat";
  private final OidcHelseIDBrukerService oidcHelseIDBrukerService;
  private final ClientRegistration clientRegistration;


  public HelseIDJwtOidcAuthenticationConverter(OidcHelseIDBrukerService oidcHelseIDBrukerService,
      ClientRegistration clientRegistration) {
    this.oidcHelseIDBrukerService = oidcHelseIDBrukerService;
    this.clientRegistration = clientRegistration;
  }


  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    Map<String, Object> claims = new HashMap<>(jwt.getClaims());

    String token = jwt.getTokenValue();
    Instant issuedAt = Instant.parse(claims.get(ISSUED_AT).toString());
    Instant expiresAt = Instant.parse(claims.get(EXPIRES_AT).toString());

    OAuth2AccessToken accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            token,
            issuedAt,
            expiresAt,
            Collections.emptySet());

    OidcIdToken oidcIdToken = new OidcIdToken(token, issuedAt, expiresAt, claims);
    OidcUserRequest oauth2UserRequest =
        new OidcUserRequest(clientRegistration, accessToken, oidcIdToken, new HashMap<>());

    OidcUser oidcUser = this.oidcHelseIDBrukerService.loadUser(oauth2UserRequest);

    return new OAuth2AuthenticationToken(
        oidcUser, oidcUser.getAuthorities(), clientRegistration.getRegistrationId());
  }
}

