package com.example.service;

import com.example.config.OAuth2ClientDetailProperties;
import com.example.utils.CertificateUtils;
import com.example.utils.JWK2PEM;
import com.example.utils.PathResolver;
import com.example.utils.XMLSec2PEM;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

@Slf4j
public class AuthorizationDetailsJwtClientParametersConverter<T extends AbstractOAuth2AuthorizationGrantRequest> implements
        Converter<T, MultiValueMap<String, String>> {

    private static final String INVALID_KEY_ERROR_CODE = "invalid_key";
    private static final String INVALID_ALGORITHM_ERROR_CODE = "invalid_algorithm";
    private static final String CLIENT_ASSERTION_TYPE_VALUE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String AUTHORIZATION_DETAILS_ORG_NR_TEMPLATE = """
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
                            "value":"%s",
                        }
                    }
                }
            }
            """;
    private final Function<ClientRegistration, JWK> jwkResolver;
    private final Map<String, OAuth2ClientDetailProperties.Registration> registrations;
    private final Map<String, JwsEncoderHolder> jwsEncoders = new ConcurrentHashMap<>();


    public AuthorizationDetailsJwtClientParametersConverter(Map<String, OAuth2ClientDetailProperties.Registration> registrations) {
        this.registrations = registrations;
        this.jwkResolver = jwkResolver(registrations);
    }

    @Override
    public MultiValueMap<String, String> convert(T authorizationGrantRequest) {
        Assert.notNull(authorizationGrantRequest, "authorizationGrantRequest cannot be null");

        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
        if (!ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(clientRegistration.getClientAuthenticationMethod())
                && !ClientAuthenticationMethod.CLIENT_SECRET_JWT
                .equals(clientRegistration.getClientAuthenticationMethod())) {
            return null;
        }

        JWK jwk = this.jwkResolver.apply(clientRegistration);
        if (jwk == null) {

            final String description = String.format("Failed to resolve JWK signing key for client registration %s check private-key in properties'.",
                    clientRegistration.getRegistrationId());

            OAuth2Error oauth2Error = new OAuth2Error(INVALID_KEY_ERROR_CODE, description, null);
            throw new OAuth2AuthorizationException(oauth2Error);
        }

        JwsAlgorithm jwsAlgorithm = resolveAlgorithm(jwk);
        if (jwsAlgorithm == null) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_ALGORITHM_ERROR_CODE,
                    "Unable to resolve JWS (signing) algorithm from JWK associated to client registration '"
                            + clientRegistration.getRegistrationId() + "'.",
                    null);
            throw new OAuth2AuthorizationException(oauth2Error);
        }

        JwsHeader.Builder headersBuilder = JwsHeader.with(jwsAlgorithm);

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(Duration.ofSeconds(60));


        JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
                .issuer(clientRegistration.getClientId())
                .subject(clientRegistration.getClientId())
                .audience(Collections.singletonList(clientRegistration.getProviderDetails().getTokenUri()))
                .id(UUID.randomUUID().toString())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt);

        final OAuth2ClientDetailProperties.Registration registration = registrations.get(clientRegistration.getClientName());
        final String orgNumber = registration.getOrgNumber();
        if (orgNumber != null) {
            String authorization_details = String.format(AUTHORIZATION_DETAILS_ORG_NR_TEMPLATE, orgNumber);
            claimsBuilder.claim("authorization_details", authorization_details);
        }

        JwsHeader jwsHeader = headersBuilder.build();
        JwtClaimsSet jwtClaimsSet = claimsBuilder.build();

        AuthorizationDetailsJwtClientParametersConverter.JwsEncoderHolder jwsEncoderHolder = this.jwsEncoders.compute(clientRegistration.getRegistrationId(),
                (clientRegistrationId, currentJwsEncoderHolder) -> {
                    if (currentJwsEncoderHolder != null && currentJwsEncoderHolder.getJwk().equals(jwk)) {
                        return currentJwsEncoderHolder;
                    }
                    JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
                    return new AuthorizationDetailsJwtClientParametersConverter.JwsEncoderHolder(new NimbusJwtEncoder(jwkSource), jwk);
                });

        JwtEncoder jwsEncoder = jwsEncoderHolder.getJwsEncoder();
        Jwt jws = jwsEncoder.encode(JwtEncoderParameters.from(jwsHeader, jwtClaimsSet));

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_VALUE);
        parameters.set(OAuth2ParameterNames.CLIENT_ASSERTION, jws.getTokenValue());

        return parameters;
    }

    private static JwsAlgorithm resolveAlgorithm(JWK jwk) {
        JwsAlgorithm jwsAlgorithm = null;

        if (jwk.getAlgorithm() != null) {
            jwsAlgorithm = SignatureAlgorithm.from(jwk.getAlgorithm().getName());
            if (jwsAlgorithm == null) {
                jwsAlgorithm = MacAlgorithm.from(jwk.getAlgorithm().getName());
            }
        }

        if (jwsAlgorithm == null) {
            if (KeyType.RSA.equals(jwk.getKeyType())) {
                jwsAlgorithm = SignatureAlgorithm.RS256;
            } else if (KeyType.EC.equals(jwk.getKeyType())) {
                jwsAlgorithm = SignatureAlgorithm.ES256;
            } else if (KeyType.OCT.equals(jwk.getKeyType())) {
                jwsAlgorithm = MacAlgorithm.HS256;
            }
        }

        return jwsAlgorithm;
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

    private Function<ClientRegistration, JWK> jwkResolver(Map<String, OAuth2ClientDetailProperties.Registration> registrations) {
        return (ClientRegistration clientRegistration) -> {
            if (clientRegistration
                    .getClientAuthenticationMethod()
                    .equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {

                final OAuth2ClientDetailProperties.Registration registration = registrations.get(clientRegistration.getClientName());
                try {
                    RSAPrivateKey privateKey;
                    if (registration.getPrivateKey().endsWith(".pem")) {
                        final String pem = Files.readString(Path.of(PathResolver.getURI(registration.getPrivateKey())));
                        privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
                    } else if (registration.getPrivateKey().endsWith(".xml")) {
                        final String pem = XMLSec2PEM.getPem(PathResolver.getInputStream(registration.getPrivateKey()));
                        privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
                    } else if (registration.getPrivateKey().endsWith(".json")) {
                        final String pem = JWK2PEM.getPem(PathResolver.getInputStream(registration.getPrivateKey()));
                        privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
                    } else {
                        final String pem = registration.getPrivateKey();
                        privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(pem);
                    }

                    RSAPublicKey publicKey = (RSAPublicKey) CertificateUtils.getPublicKey(privateKey);
                    return new RSAKey.Builder(publicKey)
                            .privateKey(privateKey)
                            .keyID(UUID.randomUUID().toString())
                            .build();
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
            return null;
        };
    }
}

