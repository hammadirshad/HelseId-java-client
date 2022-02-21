package com.example.filter;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class ExpiredTokenFilter extends OncePerRequestFilter {

    private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
    private final Duration accessTokenExpiresSkew = Duration.ofSeconds(30);
    private final Clock clock = Clock.systemUTC();
    private final DefaultRefreshTokenTokenResponseClient refreshTokenTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
    private final JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private final OidcUserService oidcUserService;

    @SneakyThrows
    @Override
    protected void doFilterInternal(
            HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse,
            FilterChain filterChain) {

        final String pathWithoutContextPath =
                new UrlPathHelper().getPathWithinApplication(httpServletRequest);
        if (pathWithoutContextPath.equals("/api") || pathWithoutContextPath.startsWith("/api/")) {
            refreshToken(httpServletRequest, httpServletResponse);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void refreshToken(HttpServletRequest httpServletRequest,
                              HttpServletResponse httpServletResponse) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2AuthenticationToken authenticationToken) {

            OAuth2AuthorizedClient authorizedClient =
                    oAuth2AuthorizedClientRepository.loadAuthorizedClient(
                            authenticationToken.getAuthorizedClientRegistrationId(), authentication,
                            httpServletRequest);

            if (authorizedClient != null && isExpired(authorizedClient.getAccessToken())) {

                ClientRegistration clientRegistration = authorizedClient.getClientRegistration();

                OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest =
                        new OAuth2RefreshTokenGrantRequest(
                                clientRegistration,
                                authorizedClient.getAccessToken(),
                                Objects.requireNonNull(authorizedClient.getRefreshToken()));

                OAuth2AccessTokenResponse accessTokenResponse =
                        refreshTokenTokenResponseClient.getTokenResponse(refreshTokenGrantRequest);

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

                oAuth2AuthorizedClientRepository.saveAuthorizedClient(
                        newAuthorizedClient, newAuthenticationToken, httpServletRequest, httpServletResponse);

                SecurityContextHolder.getContext().setAuthentication(newAuthenticationToken);
            }
        }
    }

    private Boolean isExpired(OAuth2AccessToken oAuth2AccessToken) {
        Instant now = clock.instant();
        Instant expiresAt = oAuth2AccessToken.getExpiresAt();
        return expiresAt != null && now.isAfter(expiresAt.minus(accessTokenExpiresSkew));
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

