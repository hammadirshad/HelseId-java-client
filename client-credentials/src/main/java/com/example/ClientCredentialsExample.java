package com.example;

import com.example.model.DPoPToken;
import com.example.service.HelseIDClientCredentialTokenService;
import com.example.service.HelseIDDPoPClientCredentialTokenService;
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

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientCredentialsExample implements ApplicationRunner {

  private final RestTemplateBuilder restTemplateBuilder;
  private final HelseIDClientCredentialTokenService helseIDClientCredentialTokenService;
  private final HelseIDDPoPClientCredentialTokenService helseIDDPoPClientCredentialTokenService;

  @Override
  public void run(ApplicationArguments args) {
    String requestUrl = "http://localhost:9090/api/client-name";

    try {
      OAuth2AccessToken accessToken = helseIDClientCredentialTokenService.getAccessToken();
      request(accessToken, requestUrl);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }

    log.info("----------------");

    try {
      DPoPToken dPoPToken =
          helseIDDPoPClientCredentialTokenService.getAccessToken(requestUrl, HttpMethod.GET.name());
      request(dPoPToken, requestUrl);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
    }
  }

  private void request(OAuth2AccessToken accessToken, String requestUrl) {
    log.warn("OAuth2 Token: " + accessToken.getTokenValue());
    log.warn("Scopes: " + String.join(", ", accessToken.getScopes()));
    RestTemplate restTemplate = restTemplateBuilder.build();
    HttpHeaders httpHeaders = new HttpHeaders();
    httpHeaders.setBearerAuth(accessToken.getTokenValue());
    ResponseEntity<String> responseEntity =
        restTemplate.exchange(
            requestUrl, HttpMethod.GET, new HttpEntity<String>(httpHeaders), String.class);
    if (responseEntity.hasBody()) {
      log.info("Response from API: " + responseEntity.getBody());
    }
  }

  private void request(DPoPToken dPoPToken, String requestUrl) {
    log.warn("DPoP Token: " + dPoPToken.getTokenValue());
    log.warn("DPoP Header: " + dPoPToken.getDPoPHeader());
    log.warn("Scopes: " + String.join(", ", dPoPToken.getScopes()));
    RestTemplate restTemplate = restTemplateBuilder.build();
    HttpHeaders httpHeaders = new HttpHeaders();
    httpHeaders.set("Authorization", "DPoP " + dPoPToken.getTokenValue());
    httpHeaders.set("DPoP", dPoPToken.getDPoPHeader());
    ResponseEntity<String> responseEntity =
        restTemplate.exchange(
            requestUrl, HttpMethod.GET, new HttpEntity<String>(httpHeaders), String.class);
    if (responseEntity.hasBody()) {
      log.info("Response from API using DPoP: " + responseEntity.getBody());
    }
  }
}
