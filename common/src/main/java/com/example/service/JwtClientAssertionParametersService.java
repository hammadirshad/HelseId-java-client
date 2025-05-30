package com.example.service;

import com.example.config.OAuth2ClientDetailProperties;
import com.example.config.OAuth2ClientDetailProperties.Registration;
import com.example.utils.CertificateUtils;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Slf4j
public class JwtClientAssertionParametersService {

  private static final String INVALID_KEY_ERROR_CODE = "invalid_key";
  private static final String INVALID_ALGORITHM_ERROR_CODE = "invalid_algorithm";
  private static final String CLIENT_ASSERTION_TYPE_VALUE =
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  private static final String AUTHORIZATION_DETAILS_ORG_NR_TEMPLATE =
      """
      {
          "type":"helseid_authorization",
          "practitioner_role":
          {
              "organization":
              {
                  "identifier":
                  {
                      "system":"urn:oid:2.16.578.1.12.4.1.2.101",
                      "type":"ENH",
                      "value":"%s"
                  }
              }
          }
      }
      """;
  private final Function<ClientRegistration, JWK> jwkResolver;
  private final Map<String, OAuth2ClientDetailProperties.Registration> registrations;
  private final Map<String, JwsEncoderHolder> jwsEncoders = new ConcurrentHashMap<>();

  public JwtClientAssertionParametersService(
      Map<String, OAuth2ClientDetailProperties.Registration> registrations) {
    this.registrations = registrations;
    this.jwkResolver = jwkResolver(registrations);
  }

  public MultiValueMap<String, String> buildClientAssertionParameters(
      ClientRegistration clientRegistration) {
    JWK jwk = this.jwkResolver.apply(clientRegistration);
    if (jwk == null) {

      final String description =
          String.format(
              "Failed to resolve JWK signing key for client registration %s check private-key in properties'.",
              clientRegistration.getRegistrationId());

      OAuth2Error oauth2Error = new OAuth2Error(INVALID_KEY_ERROR_CODE, description, null);
      throw new OAuth2AuthorizationException(oauth2Error);
    }

    JwsAlgorithm jwsAlgorithm = CertificateUtils.resolveAlgorithm(jwk);
    if (jwsAlgorithm == null) {
      OAuth2Error oauth2Error =
          new OAuth2Error(
              INVALID_ALGORITHM_ERROR_CODE,
              "Unable to resolve JWS (signing) algorithm from JWK associated to client registration '"
                  + clientRegistration.getRegistrationId()
                  + "'.",
              null);
      throw new OAuth2AuthorizationException(oauth2Error);
    }

    JwsHeader.Builder headersBuilder =
        JwsHeader.with(jwsAlgorithm).header("typ", "client-authentication+jwt");

    Instant issuedAt = Instant.now();
    Instant expiresAt = issuedAt.plus(Duration.ofSeconds(45));

    JwtClaimsSet.Builder claimsBuilder =
        JwtClaimsSet.builder()
            .issuer(clientRegistration.getClientId())
            .subject(clientRegistration.getClientId())
            .audience(
                Collections.singletonList(
                    clientRegistration
                        .getProviderDetails()
                        .getConfigurationMetadata()
                        .get("issuer")
                        .toString()))
            .id(UUID.randomUUID().toString())
            .issuedAt(issuedAt)
            .notBefore(issuedAt)
            .expiresAt(expiresAt);

    final OAuth2ClientDetailProperties.Registration registration =
        registrations.get(clientRegistration.getClientName());
    final String orgNumber = registration.getOrgNumber();
    if (orgNumber != null) {
      String authorization_details =
          String.format(AUTHORIZATION_DETAILS_ORG_NR_TEMPLATE, orgNumber);
      claimsBuilder.claim("authorization_details", authorization_details);
    }

    JwsHeader jwsHeader = headersBuilder.build();
    JwtClaimsSet jwtClaimsSet = claimsBuilder.build();

    JwsEncoderHolder jwsEncoderHolder =
        this.jwsEncoders.compute(
            clientRegistration.getRegistrationId(),
            (clientRegistrationId, currentJwsEncoderHolder) -> {
              if (currentJwsEncoderHolder != null && currentJwsEncoderHolder.getJwk().equals(jwk)) {
                return currentJwsEncoderHolder;
              }
              JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
              return new JwsEncoderHolder(new NimbusJwtEncoder(jwkSource), jwk);
            });

    JwtEncoder jwsEncoder = jwsEncoderHolder.getJwsEncoder();
    Jwt jws = jwsEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

    MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
    parameters.set(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_VALUE);
    parameters.set(OAuth2ParameterNames.CLIENT_ASSERTION, jws.getTokenValue());
    return parameters;
  }

  private static final class JwsEncoderHolder {

    private final JwtEncoder jwsEncoder;

    private final JWK jwk;

    private JwsEncoderHolder(JwtEncoder jwsEncoder, JWK jwk) {
      this.jwsEncoder = jwsEncoder;
      this.jwk = jwk;
    }

    private JwtEncoder getJwsEncoder() {
      return this.jwsEncoder;
    }

    private JWK getJwk() {
      return this.jwk;
    }
  }

  private Function<ClientRegistration, JWK> jwkResolver(Map<String, Registration> registrations) {
    return (ClientRegistration clientRegistration) -> {
      if (clientRegistration
          .getClientAuthenticationMethod()
          .equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {

        final OAuth2ClientDetailProperties.Registration registration =
            registrations.get(clientRegistration.getClientName());
        String privateKeyValue = registration.getPrivateKey();
        try {
          RSAPrivateKey privateKey = CertificateUtils.getRsaPrivateKey(privateKeyValue);
          return CertificateUtils.getRsaKey(privateKey, registration.getKeyId());
        } catch (Exception e) {
          log.error(e.getMessage(), e);
        }
      }
      return null;
    };
  }
}
