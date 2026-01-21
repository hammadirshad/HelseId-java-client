package com.example.config;

import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
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

  @Bean
  @Primary
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeTokenResponseClient(
          OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {

    RestClientAuthorizationCodeTokenResponseClient tokenResponseClient =
        new RestClientAuthorizationCodeTokenResponseClient();

    tokenResponseClient.addParametersConverter(
        new AuthorizationDetailsJwtClientParametersConverter<>(
            oauth2ClientKeypairProperties.getRegistration()));

    return tokenResponseClient;
  }

  @Bean
  @Primary
  public OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest> refreshTokenResponseClient(
      OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {

    RestClientRefreshTokenTokenResponseClient tokenResponseClient =
        new RestClientRefreshTokenTokenResponseClient();

    tokenResponseClient.addParametersConverter(
        new AuthorizationDetailsJwtClientParametersConverter<>(
            oauth2ClientKeypairProperties.getRegistration()));

    return tokenResponseClient;
  }
}
