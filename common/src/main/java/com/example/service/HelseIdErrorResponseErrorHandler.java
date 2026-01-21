package com.example.service;

import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.HttpClientErrorException;

public class HelseIdErrorResponseErrorHandler extends DefaultResponseErrorHandler {

  @Override
  public void handleError(URI url, HttpMethod method, ClientHttpResponse response)
      throws IOException {
    if (HttpStatus.UNAUTHORIZED == response.getStatusCode()
        && response.getHeaders().containsHeader(HttpHeaders.WWW_AUTHENTICATE)) {
      String message = response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);

      throw HttpClientErrorException.create(
          message,
          response.getStatusCode(),
          response.getStatusText(),
          response.getHeaders(),
          getResponseBody(response),
          getCharset(response));
    }

    super.handleError(response, response.getStatusCode(), url, method);
  }
}
