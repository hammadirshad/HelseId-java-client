package com.example.config;

import com.example.security.dpop.DPoPHttpHeadersConverter;
import com.example.security.dpop.DPoPProofBuilder;
import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import com.example.service.HelseIDClientCredentialTokenService;
import com.example.service.HelseIDDPoPClientCredentialTokenService;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.oauth2.client.ConditionalOnOAuth2ClientRegistrationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.MultiValueMap;

@Slf4j
@Configuration
@EnableConfigurationProperties({
  OAuth2ClientHelseIDProperties.class,
})
@ConditionalOnOAuth2ClientRegistrationProperties
public class HelseIDClientCredentialConfiguration {

  private static final String HELSEID_CREDENTIALS = "helseid-credentials";

  @Bean
  public DPoPProofBuilder dPoPProofBuilder(
      OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {
    return new DPoPProofBuilder(oauth2ClientKeypairProperties.getRegistration());
  }

  @Bean
  @Primary
  public OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
      authorizationCredentialsGrantResponseClient(
          OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {

    RestClientClientCredentialsTokenResponseClient tokenResponseClient =
        new RestClientClientCredentialsTokenResponseClient();

    tokenResponseClient.addParametersConverter(
        new AuthorizationDetailsJwtClientParametersConverter<>(
            oauth2ClientKeypairProperties.getRegistration()));

    return tokenResponseClient;
  }

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
      authorizationCredentialsGrantResponseDpopClient(
          DPoPProofBuilder dPoPProofBuilder,
          OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {

    Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>>
        jwtClientParametersConverter =
            new AuthorizationDetailsJwtClientParametersConverter<>(
                oauth2ClientKeypairProperties.getRegistration());

    Converter<OAuth2ClientCredentialsGrantRequest, HttpHeaders> dpopClientParametersConverter =
        new DPoPHttpHeadersConverter<>(jwtClientParametersConverter, dPoPProofBuilder);

    RestClientClientCredentialsTokenResponseClient tokenResponseClient =
        new RestClientClientCredentialsTokenResponseClient();
    tokenResponseClient.addParametersConverter(jwtClientParametersConverter);

    tokenResponseClient.addHeadersConverter(dpopClientParametersConverter);

    return tokenResponseClient;
  }

  @Bean
  public HelseIDClientCredentialTokenService helseIDClientCredentialTokenService(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      @Qualifier("authorizationCredentialsGrantResponseClient")
          OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
          authorizationCredentialsGrantResponseClient) {

    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(HELSEID_CREDENTIALS);

    ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsAuthorizedClientProvider =
        new ClientCredentialsOAuth2AuthorizedClientProvider();
    clientCredentialsAuthorizedClientProvider.setAccessTokenResponseClient(
        authorizationCredentialsGrantResponseClient);

    return new HelseIDClientCredentialTokenService(
        clientRegistration,
        oAuth2AuthorizedClientService,
        clientCredentialsAuthorizedClientProvider);
  }

  @Bean
  public HelseIDDPoPClientCredentialTokenService helseIdApiDPOPClientCredentialTokenService(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      DPoPProofBuilder dPoPProofBuilder,
      @Qualifier("authorizationCredentialsGrantResponseDpopClient")
          OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
          authorizationCredentialsGrantResponseDpopClient) {
    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(HELSEID_CREDENTIALS);

    ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsAuthorizedClientProvider =
        new ClientCredentialsOAuth2AuthorizedClientProvider();
    clientCredentialsAuthorizedClientProvider.setAccessTokenResponseClient(
        authorizationCredentialsGrantResponseDpopClient);

    return new HelseIDDPoPClientCredentialTokenService(
        clientRegistration,
        dPoPProofBuilder,
        oAuth2AuthorizedClientService,
        clientCredentialsAuthorizedClientProvider,
        Duration.ofMinutes(2));
  }
}
