package com.example.config;

import com.example.service.HelseIDJwtOidcAuthenticationConverter;
import com.example.service.OidcHelseIDBrukerService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
@RequiredArgsConstructor
public class HelseConfiguration {

  private final ClientRegistrationRepository clientRegistrationRepository;

  public static final String REGISTRATION_NAME = "helseid-code";

  @Bean
  public OidcHelseIDBrukerService oidcHelseIDBrukerService() {

    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(
            REGISTRATION_NAME);
    return new OidcHelseIDBrukerService(clientRegistration);
  }

  @Bean
  public Converter<Jwt, AbstractAuthenticationToken> helseIDJwtOidcAuthenticationConverter(
      OidcHelseIDBrukerService oidcHelseIDBrukerService) {
    ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(REGISTRATION_NAME);
    return new HelseIDJwtOidcAuthenticationConverter(oidcHelseIDBrukerService,
        clientRegistration);
  }

  @Bean
  public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
    return registration -> {
      String issuer = registration.getProviderDetails().getIssuerUri();
      NimbusJwtDecoder decoder =
          NimbusJwtDecoder.withIssuerLocation(issuer)
              .jwsAlgorithm(SignatureAlgorithm.RS256)
              .jwsAlgorithm(SignatureAlgorithm.PS256)
              .build();

      decoder.setJwtValidator(
          JwtValidators.createDefaultWithValidators(new OidcIdTokenValidator(registration)));
      decoder.setClaimSetConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverter());

      return decoder;
    };
  }
}
