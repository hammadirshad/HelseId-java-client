package com.example.security;


import com.example.config.OAuth2ClientResourceDetailProperties;
import com.example.service.HelseIDJwtAuthenticationConverter;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ResourceServerConfiguration {

  public final HelseIDJwtAuthenticationConverter jwtAuthenticationConverter;

  @Primary
  @Bean
  @ConditionalOnProperty(name = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri")
  JwtDecoder jwtDecoderByJwkKeySetUri(OAuth2ResourceServerProperties oAuth2ResourceServerProperties,
      OAuth2ClientResourceDetailProperties oAuth2ClientDetailProperties) {
    OAuth2ResourceServerProperties.Jwt jwtProperties = oAuth2ResourceServerProperties.getJwt();

    NimbusJwtDecoder nimbusJwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwtProperties.getJwkSetUri())
        .jwsAlgorithm(SignatureAlgorithm.from(jwtProperties.getJwsAlgorithms().get(0))).build();

    List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();

    validators.add(new JwtTimestampValidator());

    if (jwtProperties.getIssuerUri() != null) {
      validators.add(new JwtIssuerValidator(jwtProperties.getIssuerUri()));
    }

    if (oAuth2ClientDetailProperties.getAudience() != null) {
      validators.add(new JwtAudienceValidator(oAuth2ClientDetailProperties.getAudience()));
    }

    if (oAuth2ClientDetailProperties.getScope() != null) {
      validators.add(new JwtScopeValidator(oAuth2ClientDetailProperties.getScope()));
    }

    nimbusJwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validators));
    return nimbusJwtDecoder;
  }

  @Bean
  public SecurityFilterChain bearerAuthorizationFilterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(authorizeRequests -> authorizeRequests
            .requestMatchers("/", "/error", "/actuator/**")
            .permitAll()
            .requestMatchers("/api/**")
            .hasAuthority("HelseID_SCOPE_udelt:test-api/api")
            .anyRequest()
            .authenticated())
        .headers(headers -> headers.frameOptions().disable())
        .oauth2ResourceServer(
            oauth2ResourceServer ->
                oauth2ResourceServer.jwt().jwtAuthenticationConverter(jwtAuthenticationConverter))
        .build();
  }


}
