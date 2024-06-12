package com.example.security.dpop;

import com.example.config.OAuth2ClientDetailProperties.Registration;
import com.example.utils.CertificateUtils;
import com.example.utils.JWK2PEM;
import com.example.utils.PathResolver;
import com.example.utils.XMLSec2PEM;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

@Slf4j
public class DPoPProofBuilder {

  private final Map<String, Registration> registrations;

  public DPoPProofBuilder(Map<String, Registration> registrations) {

    this.registrations = registrations;
  }

  public String createDPoPProof(
      String httpMethod, String url, String nonce, ClientRegistration clientRegistration)
      throws JOSEException {
    return createDPoPProof(httpMethod, url, nonce, null, null, clientRegistration);
  }

  public String createDPoPProof(
      String httpMethod,
      String url,
      String nonce,
      String jti,
      String ath,
      ClientRegistration clientRegistration)
      throws JOSEException {
    final Registration registration = registrations.get(clientRegistration.getClientName());
    try {

      RSAPrivateKey privateKey = getRsaPrivateKey(registration);
      RSAPublicKey publicKey = (RSAPublicKey) CertificateUtils.getPublicKey(privateKey);
      JWK jwk = new RSAKey.Builder(publicKey).build();

      JWSHeader header =
          new JWSHeader.Builder(resolveAlgorithm(jwk))
              .type(new JOSEObjectType("dpop+jwt"))
              .jwk(jwk)
              .build();
      JWSSigner signer = new RSASSASigner(privateKey);

      Builder builder =
          new Builder()
              .jwtID(jti != null ? jti : UUID.randomUUID().toString())
              .issueTime(new Date())
              .claim("htm", httpMethod)
              .claim("htu", url);
      if (ath != null) {
        builder.claim("ath", ath);
      }
      if (nonce != null) {
        builder.claim("nonce", nonce);
      }
      JWTClaimsSet claimsSet = builder.build();

      SignedJWT signedJWT = new SignedJWT(header, claimsSet);
      signedJWT.sign(signer);

      return signedJWT.serialize();
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    return null;
  }

  private static JWSAlgorithm resolveAlgorithm(JWK jwk) {
    JWSAlgorithm jwsAlgorithm = null;

    if (KeyType.RSA.equals(jwk.getKeyType())) {
      jwsAlgorithm = JWSAlgorithm.RS256;
    } else if (KeyType.EC.equals(jwk.getKeyType())) {
      jwsAlgorithm = JWSAlgorithm.ES256;
    } else if (KeyType.OCT.equals(jwk.getKeyType())) {
      jwsAlgorithm = JWSAlgorithm.HS256;
    }
    return jwsAlgorithm;
  }

  private RSAPrivateKey getRsaPrivateKey(Registration registration)
      throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
    RSAPrivateKey privateKey;
    if (registration.getPrivateKey().endsWith(".pem")) {
      final String pem = Files.readString(
          Path.of(PathResolver.getURI(registration.getPrivateKey())));
      privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
    } else if (registration.getPrivateKey().endsWith(".xml")) {
      final String pem = XMLSec2PEM.getPem(
          PathResolver.getInputStream(registration.getPrivateKey()));
      privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
    } else if (registration.getPrivateKey().endsWith(".json")) {
      final String pem = JWK2PEM.getPem(PathResolver.getInputStream(registration.getPrivateKey()));
      privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
    } else {
      final String pem = registration.getPrivateKey();
      privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
    }
    return privateKey;
  }
}
