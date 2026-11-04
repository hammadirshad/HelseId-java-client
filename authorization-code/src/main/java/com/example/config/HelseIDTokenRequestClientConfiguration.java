package com.example.config;

import com.example.security.dpop.DPoPHttpHeadersConverter;
import com.example.security.dpop.DPoPProofBuilder;
import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientRefreshTokenTokenResponseClient;

@Slf4j
@Configuration
@EnableConfigurationProperties({OAuth2ClientDetailProperties.class})
@RequiredArgsConstructor
public class HelseIDTokenRequestClientConfiguration {
  private final OAuth2ClientDetailProperties clientDetailProperties;

  @Bean
  public DPoPProofBuilder dPoPProofBuilder() {
    return new DPoPProofBuilder(clientDetailProperties.getRegistration());
  }

  @Bean
  @Primary
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeTokenResponseClient() {

    RestClientAuthorizationCodeTokenResponseClient tokenResponseClient =
        new RestClientAuthorizationCodeTokenResponseClient();

    tokenResponseClient.addParametersConverter(jwtClientParametersConverter());
    tokenResponseClient.addHeadersConverter(dpopHeadersConverter());

    return tokenResponseClient;
  }

  @Bean
  @Primary
  public OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
      refreshTokenResponseClient() {

    RestClientRefreshTokenTokenResponseClient tokenResponseClient =
        new RestClientRefreshTokenTokenResponseClient();

    tokenResponseClient.addParametersConverter(jwtClientParametersConverter());
    tokenResponseClient.addHeadersConverter(dpopHeadersConverter());

    return tokenResponseClient;
  }

  private <T extends AbstractOAuth2AuthorizationGrantRequest>
      DPoPHttpHeadersConverter<T> dpopHeadersConverter() {
    return new DPoPHttpHeadersConverter<>(jwtClientParametersConverter(), dPoPProofBuilder());
  }

  private <T extends AbstractOAuth2AuthorizationGrantRequest>
      AuthorizationDetailsJwtClientParametersConverter<T> jwtClientParametersConverter() {
    return new AuthorizationDetailsJwtClientParametersConverter<>(
        clientDetailProperties.getRegistration());
  }
}
