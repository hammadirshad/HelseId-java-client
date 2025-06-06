package com.example.security;

import com.example.config.OAuth2ClientResourceDetailProperties;
import com.example.config.OAuth2ClientResourceDetailProperties.Detail;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ResourceServerConfiguration {

  @Primary
  @Bean
  @ConditionalOnProperty(name = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
  JwtDecoder jwtDecoderByJwkKeySetUri(OAuth2ResourceServerProperties oAuth2ResourceServerProperties,
      OAuth2ClientResourceDetailProperties oAuth2ClientDetailProperties) {
    OAuth2ResourceServerProperties.Jwt jwtProperties = oAuth2ResourceServerProperties.getJwt();

    NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwtProperties.getJwkSetUri())
        .jwsAlgorithm(SignatureAlgorithm.from(jwtProperties.getJwsAlgorithms().get(0)))
        .jwtProcessorCustomizer(
            (processor) ->
                processor.setJWSTypeVerifier(
                    new DefaultJOSEObjectTypeVerifier(
                        new JOSEObjectType("JWT"), new JOSEObjectType("at+jwt"))))
        .build();

    List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();

    validators.add(new JwtTimestampValidator());

    if (jwtProperties.getIssuerUri() != null) {
      validators.add(new JwtIssuerValidator(jwtProperties.getIssuerUri()));
    }

    if (oAuth2ClientDetailProperties.getDetail() != null) {
      validators.add(new JwtScopeAndAudienceValidator(oAuth2ClientDetailProperties.getDetail()));
    }

    nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
    return nimbusJwtDecoder;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http,
      HelseIDJwtAuthenticationConverter jwtAuthenticationConverter,
      OAuth2ClientResourceDetailProperties oAuth2ClientDetailProperties) throws Exception {
    return http
        .authorizeHttpRequests(
            registry -> ResourceServerConfiguration.configureAuthorizeRequests(registry,
                oAuth2ClientDetailProperties))
        .oauth2ResourceServer(
            oauth2ResourceServer ->
                oauth2ResourceServer.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(
                    jwtAuthenticationConverter)))
        .build();
  }


  static void configureAuthorizeRequests(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
          authorizeRequests,
      OAuth2ClientResourceDetailProperties oAuth2ClientDetailProperties) {
    authorizeRequests
        .requestMatchers("/",
            "/error")
        .permitAll()
        .requestMatchers("/api/**")
        .hasAnyAuthority(oAuth2ClientDetailProperties.getDetail().stream().map(Detail::getScope)
            .map(HelseIDJwtAuthenticationConverter.DEFAULT_AUTHORITY_PREFIX::concat)
            .toArray(String[]::new))
            .anyRequest()
            .authenticated();
  }
}
