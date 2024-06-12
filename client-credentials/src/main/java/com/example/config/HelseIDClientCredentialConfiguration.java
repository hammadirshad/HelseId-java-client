package com.example.config;

import com.example.security.dpop.DPoPProofBuilder;
import com.example.security.dpop.client.DPoPAccessTokenResponseClient;
import com.example.security.dpop.client.DefaultDPoPAccessTokenResponseClient;
import com.example.security.dpop.request.DPoPClientCredentialsGrantRequest;
import com.example.security.dpop.request.DPoPOClientCredentialsGrantRequestEntityConverter;
import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import com.example.service.HelseIDClientCredentialTokenService;
import com.example.service.HelseIDDPoPClientCredentialTokenService;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@Slf4j
@Configuration
@EnableConfigurationProperties({
    OAuth2ClientHelseIDProperties.class,
})
@Conditional(ClientsConfiguredCondition.class)
public class HelseIDClientCredentialConfiguration {

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
  authorizationCredentialsGrantResponseClient(
      OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {
    DefaultClientCredentialsTokenResponseClient tokenResponseClient =
        new DefaultClientCredentialsTokenResponseClient();

    OAuth2ClientCredentialsGrantRequestEntityConverter requestEntityConverter =
        new OAuth2ClientCredentialsGrantRequestEntityConverter();

    requestEntityConverter.addParametersConverter(
        new AuthorizationDetailsJwtClientParametersConverter<>(
            oauth2ClientKeypairProperties.getRegistration()));

    tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
    return tokenResponseClient;
  }

  @ConditionalOnProperty(prefix = "helseid", value = "registration-name.machine")
  @Bean
  public HelseIDClientCredentialTokenService helseIDClientCredentialTokenService(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2ClientHelseIDProperties oAuth2ClientHelseIDProperties,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
          credentialsGrantResponseClient) {
    String registrationName = oAuth2ClientHelseIDProperties.getRegistrationName().getMachine();
    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(registrationName);

    ClientCredentialsOAuth2AuthorizedClientProvider clientCredentialsAuthorizedClientProvider = new ClientCredentialsOAuth2AuthorizedClientProvider();
    clientCredentialsAuthorizedClientProvider.setAccessTokenResponseClient(
        credentialsGrantResponseClient);

    return new HelseIDClientCredentialTokenService(
        clientRegistration,
        oAuth2AuthorizedClientService,
        clientCredentialsAuthorizedClientProvider);
  }

  @Bean
  public DPoPProofBuilder dPoPProofBuilder(
      OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {
    return new DPoPProofBuilder(oauth2ClientKeypairProperties.getRegistration());
  }

  @Bean
  public DPoPAccessTokenResponseClient<DPoPClientCredentialsGrantRequest>
  authorizationCredentialsGrantResponseDpopClient(DPoPProofBuilder dPoPProofBuilder,
      OAuth2ClientDetailProperties oauth2ClientKeypairProperties) {

    AuthorizationDetailsJwtClientParametersConverter<AbstractOAuth2AuthorizationGrantRequest>
        parametersConverter =
        new AuthorizationDetailsJwtClientParametersConverter<>(
            oauth2ClientKeypairProperties.getRegistration());

    DPoPOClientCredentialsGrantRequestEntityConverter requestEntityConverter =
        new DPoPOClientCredentialsGrantRequestEntityConverter(
            parametersConverter, dPoPProofBuilder);

    return new DefaultDPoPAccessTokenResponseClient(requestEntityConverter);
  }

  @Bean
  public HelseIDDPoPClientCredentialTokenService helseIdApiDPOPClientCredentialTokenService(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2ClientHelseIDProperties oAuth2ClientHelseIDProperties,
      OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
      DPoPProofBuilder dPoPProofBuilder,
      DPoPAccessTokenResponseClient<DPoPClientCredentialsGrantRequest> credentialsGrantClient) {
    String registrationName = oAuth2ClientHelseIDProperties.getRegistrationName().getMachine();
    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(registrationName);
    return new HelseIDDPoPClientCredentialTokenService(
        clientRegistration,
        dPoPProofBuilder,
        oAuth2AuthorizedClientService,
        credentialsGrantClient,
        Duration.ofMinutes(2));
  }
}
