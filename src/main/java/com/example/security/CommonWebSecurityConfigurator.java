package com.example.security;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

public class CommonWebSecurityConfigurator {

    static void configureAuthorizeRequests(
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry
                    authorizeRequests) {
        authorizeRequests
                .mvcMatchers("/", "/error", "/actuator/**", "/mock/**")
                .permitAll()
                .antMatchers("/logout**")
                .authenticated()
                .mvcMatchers("/api/logged-in-bruker", "/api/bruker-info", "/api/login")
                .authenticated()
                .mvcMatchers("/api/**")
                .hasAnyAuthority("ROLE_ACTIVE")
                .anyRequest()
                .authenticated();
    }

    static void configurerSessionManagement(
            SessionManagementConfigurer<HttpSecurity> sessionManagement) {
        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
    }

    static void configureOAuth2Login(
            OAuth2LoginConfigurer<HttpSecurity> oauth2Login,
            OidcHelseIDBrukerService oidcHelseIDBrukerService,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
                    authorizationCodeTokenResponseClient) {
        oauth2Login
                // match with redirect uri
                .clientRegistrationRepository(clientRegistrationRepository)
                .redirectionEndpoint(redirection -> redirection.baseUri("/Auth/Token"))
                .authorizationEndpoint(
                        authorization ->
                                authorization.authorizationRequestResolver(
                                        new CodeChallengeOAuth2AuthorizationRequestResolver(
                                                clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI)))
                .userInfoEndpoint(infoEndpoint -> infoEndpoint.oidcUserService(oidcHelseIDBrukerService))
                .tokenEndpoint(
                        tokenEndpointConfig ->
                                tokenEndpointConfig.accessTokenResponseClient(
                                        authorizationCodeTokenResponseClient));
    }

    static void configureLogout(
            LogoutConfigurer<HttpSecurity> logout, LogoutSuccessHandler oidcLogoutSuccessHandler) {
        logout
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout**"))
                .logoutSuccessUrl("/")
                .logoutSuccessHandler(oidcLogoutSuccessHandler)
                .deleteCookies("JSESSIONID", "XSRF-TOKEN", "NX-ANTI-CSRF-TOKEN", "refreshToken")
                .invalidateHttpSession(true);
    }
}
