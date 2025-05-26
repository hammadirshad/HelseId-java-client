package com.example.security.dpop;

import com.example.config.OAuth2ClientDetailProperties.Registration;
import com.example.utils.CertificateUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtClaimsSet.Builder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Slf4j
public class DPoPProofBuilder {

  private final Map<String, Registration> registrations;

  public DPoPProofBuilder(Map<String, Registration> registrations) {

    this.registrations = registrations;
  }

  public String createDPoPProof(
      String httpMethod, String url, String nonce, ClientRegistration clientRegistration)
      throws JOSEException {
    return createDPoPProof(httpMethod, url, nonce, null, clientRegistration);
  }

  public String createDPoPProof(
      String httpMethod,
      String url,
      String nonce,
      String ath,
      ClientRegistration clientRegistration) {
    final Registration registration = registrations.get(clientRegistration.getClientName());
    try {

      RSAPrivateKey privateKey = getRsaPrivateKey(registration);
      RSAKey rsaKey = CertificateUtils.getRsaKey(privateKey, null);

      JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
      NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

      JwsHeader jwsHeader =
          JwsHeader.with(CertificateUtils.resolveAlgorithm(rsaKey))
              .jwk(rsaKey.toPublicJWK().toJSONObject())
              .header("typ", "dpop+jwt")
              .build();

      Builder builder =
          JwtClaimsSet.builder().issuedAt(Instant.now()).claim("htm", httpMethod).claim("htu", url);

      if (ath != null) {
        builder.claim("ath", ath);
      }
      if (nonce != null) {
        builder.claim("nonce", nonce);
      }
      JwtClaimsSet claims = builder.id(UUID.randomUUID().toString()).build();

      Jwt jws = jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
      return jws.getTokenValue();
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return null;
  }

  private RSAPrivateKey getRsaPrivateKey(Registration registration)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    String privateKeyValue = registration.getPrivateKey();
    return CertificateUtils.getRsaPrivateKey(privateKeyValue);
  }
}
