package com.example.security;

import com.example.config.OAuth2ClientDetailProperties;
import com.example.config.OAuth2ClientHelseIDProperties;
import com.example.filter.ExpiredTokenFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Order(2)
@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final OAuth2ClientDetailProperties logoutProperties;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2ClientHelseIDProperties helseIDProperties;
    private final OidcHelseIDBrukerService oidcHelseIDBrukerService;
    private final ExpiredTokenFilter expiredTokenFilter;
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
            authorizationCodeTokenResponseClient;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(CommonWebSecurityConfigurator.webSecurityRequestMatcher())
                .authorizeRequests(CommonWebSecurityConfigurator::configureAuthorizeRequests)
                .addFilterAfter(expiredTokenFilter, FilterSecurityInterceptor.class)
                .sessionManagement(CommonWebSecurityConfigurator::configurerSessionManagement)
                .headers(headers -> headers.frameOptions().disable())
                .oauth2Login(
                        oauth2Login ->
                                CommonWebSecurityConfigurator.configureOAuth2Login(
                                        oauth2Login,
                                        oidcHelseIDBrukerService,
                                        loginClientRegistrationRepository(),
                                        authorizationCodeTokenResponseClient))
                .logout(
                        logout ->
                                CommonWebSecurityConfigurator.configureLogout(logout, oidcLogoutSuccessHandler()));
    }

    public ClientRegistrationRepository loginClientRegistrationRepository() {
        ClientRegistration clientRegistration =
                clientRegistrationRepository.findByRegistrationId(
                        helseIDProperties.getRegistrationName().getLogin());
        return new InMemoryClientRegistrationRepository(clientRegistration);
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        final OAuth2ClientDetailProperties.Registration registration =
                logoutProperties.getRegistration().get(helseIDProperties.getRegistrationName().getLogin());
        OidcClientInitiatedLogoutSuccessHandler successHandler =
                new OidcClientInitiatedLogoutSuccessHandler(loginClientRegistrationRepository());
        successHandler.setPostLogoutRedirectUri(registration.getRedirectUri());
        return successHandler;
    }

    @Bean
    public CsrfTokenRepository csrfTokenRepository() {
        CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
        csrfTokenRepository.setCookieHttpOnly(false);
        csrfTokenRepository.setCookiePath("/");
        return csrfTokenRepository;
    }

    @Bean
    public RequestCache refererRequestCache() {
        return new HttpSessionRequestCache() {
            @Override
            public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
                String referrer = request.getHeader("referer");
                if (referrer != null) {
                    request
                            .getSession()
                            .setAttribute("SPRING_SECURITY_SAVED_REQUEST", new SimpleSavedRequest(referrer));
                } else {
                    super.saveRequest(request, response);
                }
            }
        };
    }
}
