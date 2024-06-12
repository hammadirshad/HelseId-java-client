package com.example.security.dpop;

import com.example.config.DPoPProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.dpop.JWKThumbprintConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Map;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Service
public class DPoPTokenValidator {

  private final DPoPProtectedResourceRequestVerifier verifier;
  private final DPoPAuthorizationTokenResolver dPoPAuthorizationTokenResolver =
      new DPoPAuthorizationTokenResolver();
  private final DPoPHeaderTokenResolver dPoPTokenResolver = new DPoPHeaderTokenResolver();

  public DPoPTokenValidator(DPoPProperties dPoPCheckerProperties) {

    SingleUseChecker<Map.Entry<DPoPIssuer, JWTID>> singleUseChecker =
        new DefaultDPoPSingleUseChecker(dPoPCheckerProperties.getJtiMaxAgeSeconds());
    verifier =
        new DPoPProtectedResourceRequestVerifier(
            dPoPCheckerProperties.getSupportedAlgs(),
            dPoPCheckerProperties.getProofMaxAgeSeconds(),
            singleUseChecker);
  }

  /**
   * Validates the DPoP token and associated headers.
   *
   * @throws ParseException                 if there's an issue with accessToken or dPoPHeader
   *                                        parsing.
   * @throws URISyntaxException             if there's an issue with Request URL processing.
   * @throws AccessTokenValidationException if there's an issue with access token validation.
   * @throws InvalidDPoPProofException      if the DPoP proof is invalid.
   * @throws JOSEException                  if there's an issue with JOSE processing.
   */
  public void validate(HttpServletRequest request)
      throws ParseException,
      URISyntaxException,
      JOSEException,
      AccessTokenValidationException,
      InvalidDPoPProofException {
    String dPoPHeader = dPoPTokenResolver.resolve(request);
    String accessTokenString = dPoPAuthorizationTokenResolver.resolve(request);

    if (accessTokenString == null) {
      throw new JwtException("Missing DPoP Authorization or DPoP header");
    }

    if (dPoPHeader == null) {
      throw new JwtException("Missing DPoP header");
    }

    SignedJWT dpopJwt = SignedJWT.parse(dPoPHeader);

    DPoPAccessToken accessToken = new DPoPAccessToken(accessTokenString);
    SignedJWT accessTokenJwt = SignedJWT.parse(accessTokenString);
    JWTClaimsSet accessTokenJwtJWTClaimsSet = accessTokenJwt.getJWTClaimsSet();

    String clientId = accessTokenJwtJWTClaimsSet.getStringClaim("client_id");
    if (clientId == null) {
      throw new JwtException("Missing client_id in access token");
    }

    if (dpopJwt.getHeader().getJWK().isPrivate()) {
      throw new JwtException("jwk header contains a symmetric key");
    }

    DPoPIssuer dPoPIssuer = new DPoPIssuer(new ClientID(clientId));
    JWKThumbprintConfirmation cnf = JWKThumbprintConfirmation.parse(accessTokenJwtJWTClaimsSet);

    String httpMethod = request.getMethod();
    URI httpURI = new URI(request.getRequestURL().toString());

    verifier.verify(httpMethod, httpURI, dPoPIssuer, dpopJwt, accessToken, cnf, null);
  }
}
