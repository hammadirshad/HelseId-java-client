package com.example.service;

import com.example.security.OidcHelseIDBrukerService;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
public class HelseIDJwtAuthenticationConverter
        implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final String EXPIRES_AT = "exp";
    private static final String ISSUED_AT = "iat";
    private final ClientRegistration clientRegistration;
    private final OidcHelseIDBrukerService oidcHelseIDBrukerService;

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Map<String, Object> claims = new HashMap<>(jwt.getClaims());
        boolean idToken =
                claims.containsKey(IdTokenClaimNames.AUD) && claims.containsKey(IdTokenClaimNames.IAT);

        String token = jwt.getTokenValue();
        Instant issuedAt = Instant.parse(claims.get(ISSUED_AT).toString());
        Instant expiresAt = Instant.parse(claims.get(EXPIRES_AT).toString());

        OAuth2AccessToken accessToken =
                new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        token,
                        issuedAt,
                        expiresAt,
                        idToken ? Collections.emptySet() : clientRegistration.getScopes());

        OidcIdToken oidcIdToken = new OidcIdToken(token, issuedAt, expiresAt, claims);
        Map<String, Object> additionalParameters = new HashMap<>();

        if (idToken) {
            additionalParameters.put(OidcParameterNames.ID_TOKEN, token);
        }

        OidcUserRequest oauth2UserRequest =
                new OidcUserRequest(clientRegistration, accessToken, oidcIdToken, additionalParameters);

        OidcUser oidcUser = this.oidcHelseIDBrukerService.loadUser(oauth2UserRequest);

        return new OAuth2AuthenticationToken(
                oidcUser, oidcUser.getAuthorities(), clientRegistration.getRegistrationId());
    }
}

