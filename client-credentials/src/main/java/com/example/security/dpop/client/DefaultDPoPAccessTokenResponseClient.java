package com.example.security.dpop.client;

import com.example.security.dpop.request.DPoPClientCredentialsGrantRequest;
import com.example.security.dpop.response.DPoPAccessTokenResponse;
import java.util.List;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;

public class DefaultDPoPAccessTokenResponseClient
    implements DPoPAccessTokenResponseClient<DPoPClientCredentialsGrantRequest> {

  private static final String INVALID_TOKEN_RESPONSE_ERROR_CODE = "invalid_token_response";

  private final Converter<DPoPClientCredentialsGrantRequest, RequestEntity<?>>
      requestEntityConverter;

  private final RestOperations restOperations;

  public DefaultDPoPAccessTokenResponseClient(
      Converter<DPoPClientCredentialsGrantRequest, RequestEntity<?>> requestEntityConverter) {
    this.requestEntityConverter = requestEntityConverter;

    this.restOperations =
        new RestTemplateBuilder()
            .additionalMessageConverters(
                new FormHttpMessageConverter(), new DPoPAccessTokenResponseHttpMessageConverter())
            .errorHandler(new OAuth2ErrorResponseErrorHandler())
            .build();
  }

  @Override
  public DPoPAccessTokenResponse getTokenResponse(
      DPoPClientCredentialsGrantRequest clientCredentialsGrantRequest) {
    RequestEntity<?> request = this.requestEntityConverter.convert(clientCredentialsGrantRequest);
    try {
      ResponseEntity<DPoPAccessTokenResponse> response =
          this.restOperations.exchange(request, DPoPAccessTokenResponse.class);
      return response.getBody();
    } catch (RestClientException ex) {
      OAuth2Error oauth2Error =
          new OAuth2Error(
              INVALID_TOKEN_RESPONSE_ERROR_CODE,
              "An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response: "
              + ex.getMessage(),
              null);
      throw new OAuth2AuthorizationException(oauth2Error, ex);
    }
  }
}
