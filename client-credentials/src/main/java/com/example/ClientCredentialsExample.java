package com.example;

import com.example.service.HelseIDClientCredentialTokenService;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.text.ParseException;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientCredentialsExample implements ApplicationRunner {

    private final RestTemplateBuilder restTemplateBuilder;
    private final HelseIDClientCredentialTokenService helseIDClientCredentialTokenService;

    @Override
    public void run(ApplicationArguments args) throws ParseException {
        final OAuth2AccessToken accessToken = helseIDClientCredentialTokenService.getAccessToken();
        log.info("OAuth2Token: " + accessToken.getTokenValue());
        log.info("Scopes: " + accessToken.getScopes().toString());

        JWT jwt = JWTParser.parse(accessToken.getTokenValue());
        log.info("Claims: " + jwt.getJWTClaimsSet().getClaims().toString());

        RestTemplate restTemplate = restTemplateBuilder.build();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(accessToken.getTokenValue());
        ResponseEntity<String> responseEntity = restTemplate.exchange("http://localhost:8080/api/secured", HttpMethod.GET,
                new HttpEntity<String>(httpHeaders), String.class);
        if (responseEntity.hasBody()) {
            log.info(responseEntity.getBody());
        }
    }
}
