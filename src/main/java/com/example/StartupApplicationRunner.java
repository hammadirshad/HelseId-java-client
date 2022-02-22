package com.example;

import com.example.service.HelseIDClientCredentialTokenService;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;

import java.text.ParseException;

@Slf4j
@Service
@Profile("default")
@RequiredArgsConstructor
public class StartupApplicationRunner implements ApplicationRunner {

    private final HelseIDClientCredentialTokenService helseIDClientCredentialTokenService;

    @Override
    public void run(ApplicationArguments args) throws ParseException {
        final OAuth2AccessToken accessToken = helseIDClientCredentialTokenService.getAccessToken();
        log.info(accessToken.getTokenValue());
        log.info(accessToken.getScopes().toString());
        log.info(JWTParser.parse(accessToken.getTokenValue()).getJWTClaimsSet().getClaims().toString());
    }
}
