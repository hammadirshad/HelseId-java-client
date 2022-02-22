package com.example.config;

import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import com.example.utils.CertificateUtils;
import com.example.utils.PathResolver;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Configuration
@EnableConfigurationProperties({
        OAuth2ClientKeypairProperties.class,
        OAuth2ClientLogoutProperties.class
})
@RequiredArgsConstructor
public class HelseIDTokenRequestClientConfiguration {
    private final OAuth2ClientKeypairProperties oauth2ClientKeypairProperties;

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
    authorizationCodeTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();

        OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter =
                new OAuth2AuthorizationCodeGrantRequestEntityConverter();

        requestEntityConverter.addParametersConverter(
                new AuthorizationDetailsJwtClientParametersConverter<>(
                        jwkResolver(oauth2ClientKeypairProperties.getRegistration()), null));

        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
        return tokenResponseClient;
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest>
    authorizationCredentialsGrantResponseClient() {
        DefaultClientCredentialsTokenResponseClient tokenResponseClient =
                new DefaultClientCredentialsTokenResponseClient();

        OAuth2ClientCredentialsGrantRequestEntityConverter requestEntityConverter =
                new OAuth2ClientCredentialsGrantRequestEntityConverter();

        requestEntityConverter.addParametersConverter(
                new AuthorizationDetailsJwtClientParametersConverter<>(
                        jwkResolver(oauth2ClientKeypairProperties.getRegistration()), null));

        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
        return tokenResponseClient;
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2RefreshTokenGrantRequest>
    authorizationRefreshTokenTokenResponseClient() {
        DefaultRefreshTokenTokenResponseClient tokenResponseClient =
                new DefaultRefreshTokenTokenResponseClient();

        OAuth2RefreshTokenGrantRequestEntityConverter requestEntityConverter =
                new OAuth2RefreshTokenGrantRequestEntityConverter();
        requestEntityConverter.addParametersConverter(
                new AuthorizationDetailsJwtClientParametersConverter<>(
                        jwkResolver(oauth2ClientKeypairProperties.getRegistration()), null));

        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
        return tokenResponseClient;
    }

    private Function<ClientRegistration, JWK> jwkResolver(Map<String, OAuth2ClientKeypairProperties.Registration> registrations) {
        return (ClientRegistration clientRegistration) -> {
            if (clientRegistration
                    .getClientAuthenticationMethod()
                    .equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {

                final OAuth2ClientKeypairProperties.Registration registration = registrations.get(clientRegistration.getClientName());
                try {
                    RSAPrivateKey privateKey;
                    if (registration.getPrivateKey().endsWith(".pem")) {
                        privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(PathResolver.getInputStream(registration.getPrivateKey()));
                    } else {
                        privateKey = (RSAPrivateKey) CertificateUtils.getPrivateKey(registration.getPrivateKey());
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

