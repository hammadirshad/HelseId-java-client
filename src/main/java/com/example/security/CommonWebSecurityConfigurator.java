package com.example.security;

import com.example.service.AntPathRequestMatcherWrapper;
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

import javax.servlet.http.HttpServletRequest;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

public class CommonWebSecurityConfigurator {

    static AntPathRequestMatcherWrapper webSecurityRequestMatcher() {
        return new AntPathRequestMatcherWrapper("/**") {
            @Override
            protected boolean precondition(HttpServletRequest request) {
                return !String.valueOf(request.getHeader("Authorization")).contains("Bearer");
            }
        };
    }

    static AntPathRequestMatcherWrapper resourceServerRequestMatcher() {
        return new AntPathRequestMatcherWrapper("/api/**") {
            @Override
            protected boolean precondition(HttpServletRequest request) {
                return String.valueOf(request.getHeader("Authorization")).contains("Bearer");
            }
        };
    }

    static void configureAuthorizeRequests(
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry
                    authorizeRequests) {
        authorizeRequests
                .mvcMatchers("/", "/error", "/actuator/**", "/webjars/**")
                .permitAll()
                .antMatchers("/logout**")
                .authenticated()
                .mvcMatchers("/api/bruker-info", "/api/login")
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
            String baseRedirectUri,
            OAuth2LoginConfigurer<HttpSecurity> oauth2Login,
            OidcHelseIDBrukerService oidcHelseIDBrukerService,
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
                    authorizationCodeTokenResponseClient) {
        oauth2Login
                // match with redirect uri
                .clientRegistrationRepository(clientRegistrationRepository)
                .redirectionEndpoint(redirection -> redirection.baseUri(baseRedirectUri))
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
