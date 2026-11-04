package com.example.config;

import com.example.security.dpop.DPoPHttpHeadersConverter;
import com.example.security.dpop.DPoPProofBuilder;
import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import com.example.service.HelseIDDPoPClientCredentialTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.ConditionalOnOAuth2ClientRegistrationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@Slf4j
@Configuration
@EnableConfigurationProperties({
  OAuth2ClientHelseIDProperties.class,
})
@ConditionalOnOAuth2ClientRegistrationProperties
@RequiredArgsConstructor
public class HelseIDClientCredentialConfiguration {
  private final OAuth2ClientDetailProperties clientDetailProperties;

  private static final String HELSEID_CREDENTIALS = "helseid-credentials";

  @Bean
  public DPoPProofBuilder dPoPProofBuilder() {
    return new DPoPProofBuilder(clientDetailProperties.getRegistration());
  }

  @Bean
  @Primary
  public OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
      authorizationCredentialsGrantResponseDpopClient() {
    RestClientClientCredentialsTokenResponseClient tokenResponseClient =
        new RestClientClientCredentialsTokenResponseClient();

    tokenResponseClient.addParametersConverter(jwtClientParametersConverter());
    tokenResponseClient.addHeadersConverter(dpopHeadersConverter());

    return tokenResponseClient;
  }

  @Bean
  public HelseIDDPoPClientCredentialTokenService helseIdApiDPOPClientCredentialTokenService(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      DPoPProofBuilder dPoPProofBuilder,
      OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
          dPoPTokenResponseClient) {
    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(HELSEID_CREDENTIALS);

    ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsAuthorizedClientProvider =
        new ClientCredentialsOAuth2AuthorizedClientProvider();
    clientCredentialsAuthorizedClientProvider.setAccessTokenResponseClient(dPoPTokenResponseClient);

    return new HelseIDDPoPClientCredentialTokenService(
        clientRegistration,
        dPoPProofBuilder,
        oAuth2AuthorizedClientService,
        clientCredentialsAuthorizedClientProvider);
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
