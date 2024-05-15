package com.example.security;

import com.example.config.OAuth2ClientDetailProperties;
import com.example.config.OAuth2ClientHelseIDProperties;
import com.example.filter.ExpiredTokenFilter;
import com.example.service.HelseIDJwtOidcAuthenticationConverter;
import com.example.service.OidcHelseIDBrukerService;
import com.example.utils.AntPathRequestMatcherWrapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {

  private final OAuth2ClientDetailProperties oAuth2ClientDetailProperties;
  private final ClientRegistrationRepository clientRegistrationRepository;
  private final OAuth2ClientHelseIDProperties helseIDProperties;
  private final OidcHelseIDBrukerService oidcHelseIDBrukerService;
  private final ExpiredTokenFilter expiredTokenFilter;
  private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeTokenResponseClient;

  @Bean
  public SecurityFilterChain bearerAuthorizationFilterChain(HttpSecurity http,
      HelseIDJwtOidcAuthenticationConverter jwtAuthenticationConverter) throws Exception {
    return http
        .securityMatcher(new AntPathRequestMatcherWrapper("/api/**") {
          @Override
          protected boolean precondition(HttpServletRequest request) {
            return String.valueOf(request.getHeader("Authorization")).contains("Bearer");
          }
        })
        .authorizeHttpRequests(WebSecurityConfiguration::configureAuthorizeRequests)
        .sessionManagement(this::configurerSessionManagement)
        .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
        .oauth2ResourceServer(
            oauth2ResourceServer ->
                oauth2ResourceServer.jwt(jwtConfigurer ->jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)))
        .build();
  }

  @Bean
  public SecurityFilterChain configure(HttpSecurity http) throws Exception {
    return http
        .securityMatcher(new AntPathRequestMatcherWrapper("/**") {
          @Override
          protected boolean precondition(HttpServletRequest request) {
            return !String.valueOf(request.getHeader("Authorization")).contains("Bearer");
          }
        })
        .authorizeHttpRequests(WebSecurityConfiguration::configureAuthorizeRequests)
        .addFilterAfter(expiredTokenFilter, AuthorizationFilter.class)
        .sessionManagement(this::configurerSessionManagement)
            .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
        .oauth2Login(
            oauth2Login ->
                this.configureOAuth2Login(
                    oAuth2ClientDetailProperties.getRegistration(
                            helseIDProperties.getRegistrationName().getLogin())
                        .getBaseRedirectUri(),
                    oauth2Login,
                    oidcHelseIDBrukerService,
                    loginClientRegistrationRepository(),
                    authorizationCodeTokenResponseClient))
        .logout(
            logout ->
                WebSecurityConfiguration.configureLogout(logout, oidcLogoutSuccessHandler()))
        .build();
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
        oAuth2ClientDetailProperties.getRegistration(
            helseIDProperties.getRegistrationName().getLogin());
    OidcClientInitiatedLogoutSuccessHandler successHandler =
        new OidcClientInitiatedLogoutSuccessHandler(loginClientRegistrationRepository());
    successHandler.setPostLogoutRedirectUri(registration.getPostLogoutRedirectUri());
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


  static void configureAuthorizeRequests(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
          authorizeRequests) {
    authorizeRequests
        .requestMatchers("/",
            "/error",
            "/actuator/**",
            "/webjars/**")
        .permitAll()
        .requestMatchers("/api/**")
        .hasAnyAuthority("ROLE_ACTIVE")
        .requestMatchers("/logout**",
            "/api/token-info",
            "/api/login")
        .authenticated()
        .anyRequest()
        .authenticated();
  }

  private void configurerSessionManagement(
      SessionManagementConfigurer<HttpSecurity> sessionManagement) {
    sessionManagement.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
  }

  private void configureOAuth2Login(
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
                    authorizationRequestResolverCodeChallenge(clientRegistrationRepository)))
        .userInfoEndpoint(infoEndpoint -> infoEndpoint.oidcUserService(oidcHelseIDBrukerService))
        .tokenEndpoint(
            tokenEndpointConfig ->
                tokenEndpointConfig.accessTokenResponseClient(
                    authorizationCodeTokenResponseClient));
  }

  private OAuth2AuthorizationRequestResolver authorizationRequestResolverCodeChallenge(
      ClientRegistrationRepository clientRegistrationRepository) {
    DefaultOAuth2AuthorizationRequestResolver resolver =
        new DefaultOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository,
            OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    resolver.setAuthorizationRequestCustomizer(
        customizer -> {
          StringKeyGenerator secureKeyGenerator =
              new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
          String codeVerifier = secureKeyGenerator.generateKey();
          try {
            byte[] digest =
                MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

            customizer
                .attributes(
                    attributes -> attributes.put(PkceParameterNames.CODE_VERIFIER, codeVerifier))
                .additionalParameters(
                    additionalParameters ->
                        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256"))
                .additionalParameters(
                    additionalParameters ->
                        additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, codeChallenge));

          } catch (NoSuchAlgorithmException e) {
            log.error(e.getMessage(), e);
          }
        });
    return resolver;
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
