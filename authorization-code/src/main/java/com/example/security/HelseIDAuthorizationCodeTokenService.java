package com.example.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Service
public class HelseIDAuthorizationCodeTokenService {

  private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
  private final Duration accessTokenExpiresSkew = Duration.ofSeconds(30);
  private final Clock clock = Clock.systemUTC();
  private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory =
      new OidcIdTokenDecoderFactory();

  private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
  private final OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenClient;
  private final OidcUserService oidcUserService;

  public HelseIDAuthorizationCodeTokenService(
      OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository,
      OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenClient,
      OidcUserService oidcUserService) {
    this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
    this.refreshTokenClient = refreshTokenClient;
    this.oidcUserService = oidcUserService;
  }

  public OAuth2AccessToken getAccessTokenOrRefresh(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      boolean authenticate) {
    return getAccessTokenOrRefresh(
        httpServletRequest, httpServletResponse, accessTokenExpiresSkew, authenticate);
  }

  public OAuth2AccessToken getAccessTokenOrRefresh(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      Duration accessTokenExpiresSkew,
      boolean authenticate) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication instanceof OAuth2AuthenticationToken authenticationToken) {

      OAuth2AuthorizedClient authorizedClient =
          oAuth2AuthorizedClientRepository.loadAuthorizedClient(
              authenticationToken.getAuthorizedClientRegistrationId(),
              authentication,
              httpServletRequest);

      if (authorizedClient != null) {
        ClientRegistration clientRegistration = authorizedClient.getClientRegistration();

        if (clientRegistration.getScopes().contains("offline_access")
            && isExpired(authorizedClient.getAccessToken(), accessTokenExpiresSkew)
            && isValidRefreshToken(authorizedClient.getRefreshToken())) {

          if (authenticate) {
            authorizedClient =
                getOpenIdAuthorizedClient(
                    httpServletRequest,
                    httpServletResponse,
                    authenticationToken,
                    clientRegistration,
                    authorizedClient);
          } else {
            authorizedClient =
                getOAuthAuthorizedClient(
                    httpServletRequest,
                    httpServletResponse,
                    authenticationToken,
                    accessTokenExpiresSkew,
                    authorizedClient);
          }
        }
      }
      return authorizedClient != null ? authorizedClient.getAccessToken() : null;
    }
    return null;
  }

  private OAuth2AuthorizedClient getOAuthAuthorizedClient(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      OAuth2AuthenticationToken authenticationToken,
      Duration accessTokenExpiresSkew,
      OAuth2AuthorizedClient authorizedClient) {
    OAuth2AuthorizationContext context =
        OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
            .principal(authenticationToken)
            .build();
    OAuth2AuthorizedClient newAuthorizedClient =
        getRefreshTokenAuthorizedClientProvider(refreshTokenClient, accessTokenExpiresSkew)
            .authorize(context);
    oAuth2AuthorizedClientRepository.saveAuthorizedClient(
        newAuthorizedClient, authenticationToken, httpServletRequest, httpServletResponse);
    return newAuthorizedClient;
  }

  private OAuth2AuthorizedClient getOpenIdAuthorizedClient(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      OAuth2AuthenticationToken authenticationToken,
      ClientRegistration clientRegistration,
      OAuth2AuthorizedClient authorizedClient) {

    OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest =
        new OAuth2RefreshTokenGrantRequest(
            clientRegistration,
            authorizedClient.getAccessToken(),
            authorizedClient.getRefreshToken());

    OAuth2AccessTokenResponse accessTokenResponse =
        refreshTokenClient.getTokenResponse(refreshTokenGrantRequest);

    OidcIdToken idToken = createOidcToken(clientRegistration, accessTokenResponse);

    OidcUser oidcUser =
        oidcUserService.loadUser(
            new OidcUserRequest(
                clientRegistration,
                accessTokenResponse.getAccessToken(),
                idToken,
                accessTokenResponse.getAdditionalParameters()));

    OAuth2AuthenticationToken newAuthenticationToken =
        new OAuth2AuthenticationToken(
            oidcUser,
            oidcUser.getAuthorities(),
            authenticationToken.getAuthorizedClientRegistrationId());

    OAuth2AuthorizedClient newAuthorizedClient =
        new OAuth2AuthorizedClient(
            clientRegistration,
            authenticationToken.getName(),
            accessTokenResponse.getAccessToken(),
            accessTokenResponse.getRefreshToken());
    SecurityContextHolder.getContext().setAuthentication(newAuthenticationToken);

    oAuth2AuthorizedClientRepository.saveAuthorizedClient(
        newAuthorizedClient, newAuthenticationToken, httpServletRequest, httpServletResponse);
    return newAuthorizedClient;
  }

  private Boolean isExpired(OAuth2AccessToken oAuth2AccessToken, Duration accessTokenExpiresSkew) {
    Instant now = clock.instant();
    Instant expiresAt = oAuth2AccessToken.getExpiresAt();
    return expiresAt != null && now.isAfter(expiresAt.minus(accessTokenExpiresSkew));
  }

  private Boolean isValidRefreshToken(OAuth2RefreshToken refreshToken) {
    if (refreshToken == null) {
      return false;
    }
    Instant now = clock.instant();
    Instant expiresAt = refreshToken.getExpiresAt();
    return expiresAt == null || now.isBefore(expiresAt.minus(accessTokenExpiresSkew));
  }

  private RefreshTokenOAuth2AuthorizedClientProvider getRefreshTokenAuthorizedClientProvider(
      OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenClient,
      Duration clockSkew) {
    RefreshTokenOAuth2AuthorizedClientProvider refreshTokenClientProvider =
        new RefreshTokenOAuth2AuthorizedClientProvider();
    refreshTokenClientProvider.setAccessTokenResponseClient(refreshTokenClient);
    refreshTokenClientProvider.setClockSkew(clockSkew);
    return refreshTokenClientProvider;
  }

  private OidcIdToken createOidcToken(
      ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
    JwtDecoder jwtDecoder = jwtDecoderFactory.createDecoder(clientRegistration);
    Jwt jwt;
    try {
      jwt =
          jwtDecoder.decode(
              (String)
                  accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN));
    } catch (JwtException ex) {
      OAuth2Error invalidIdTokenError =
          new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, ex.getMessage(), null);
      throw new OAuth2AuthenticationException(
          invalidIdTokenError, invalidIdTokenError.toString(), ex);
    }
    return new OidcIdToken(
        jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());
  }
}

