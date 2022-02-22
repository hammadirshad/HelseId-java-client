package com.example.config;

import com.example.service.AuthorizationDetailsJwtClientParametersConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.endpoint.*;

@Slf4j
@Configuration
@EnableConfigurationProperties({
        OAuth2ClientDetailProperties.class
})
@RequiredArgsConstructor
public class HelseIDTokenRequestClientConfiguration {
    private final OAuth2ClientDetailProperties oauth2ClientKeypairProperties;

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
    authorizationCodeTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();

        OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter =
                new OAuth2AuthorizationCodeGrantRequestEntityConverter();

        requestEntityConverter.addParametersConverter(
                new AuthorizationDetailsJwtClientParametersConverter<>(oauth2ClientKeypairProperties.getRegistration()));

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
                new AuthorizationDetailsJwtClientParametersConverter<>(oauth2ClientKeypairProperties.getRegistration()));

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
                new AuthorizationDetailsJwtClientParametersConverter<>(oauth2ClientKeypairProperties.getRegistration()));

        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
        return tokenResponseClient;
    }

}

