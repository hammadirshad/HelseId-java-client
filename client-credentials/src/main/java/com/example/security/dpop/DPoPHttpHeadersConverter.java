package com.example.security.dpop;

import com.nimbusds.jose.JOSEException;
import java.net.URI;
import java.util.Collections;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

public class DPoPHttpHeadersConverter<T extends OAuth2ClientCredentialsGrantRequest>
    implements Converter<T, HttpHeaders> {

  private final Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>>
      parametersConverter;
  private final DPoPProofBuilder dPoPProofBuilder;
  private final RestOperations restOperations;

  public DPoPHttpHeadersConverter(
      Converter<OAuth2ClientCredentialsGrantRequest, MultiValueMap<String, String>>
          parametersConverter,
      DPoPProofBuilder dPoPProofBuilder) {
    this.parametersConverter = parametersConverter;
    this.dPoPProofBuilder = dPoPProofBuilder;
    this.restOperations = new RestTemplateBuilder().build();
  }

  @Override
  public HttpHeaders convert(T authorizationGrantRequest) {
    Assert.notNull(authorizationGrantRequest, "authorizationGrantRequest cannot be null");
    ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();

    URI tokenUri = getTokenUri(clientRegistration);

    MultiValueMap<String, String> parameters =
        getParameters(authorizationGrantRequest, clientRegistration);
    MultiValueMap<String, String> convertedParameters =
        parametersConverter.convert(authorizationGrantRequest);
    if (convertedParameters != null) {
      parameters.addAll(convertedParameters);
    }

    HttpHeaders httpHeaders = new HttpHeaders();
    httpHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
    httpHeaders.setContentType(
        MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8"));

    String dPoPProofWithNonce = buildDPoPProof(tokenUri, parameters, clientRegistration);
    if (dPoPProofWithNonce != null) {
      httpHeaders.set("DPoP", dPoPProofWithNonce);
    }

    return httpHeaders;
  }

  private MultiValueMap<String, String> getParameters(
      OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest,
      ClientRegistration clientRegistration) {
    MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
    parameters.add(
        OAuth2ParameterNames.GRANT_TYPE, clientCredentialsGrantRequest.getGrantType().getValue());
    if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
      parameters.add(
          OAuth2ParameterNames.SCOPE,
          StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
    }
    return parameters;
  }

  private URI getTokenUri(ClientRegistration clientRegistration) {
    return UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getTokenUri())
        .build()
        .toUri();
  }

  private String buildDPoPProof(
      URI tokenUri, MultiValueMap<String, String> parameters, ClientRegistration clientRegistration) {

    try {

      String dPoPProofWithoutNonce =
          dPoPProofBuilder.createDPoPProof(
              HttpMethod.POST.name(), tokenUri.toString(), null, clientRegistration);

      HttpHeaders httpHeaders = new HttpHeaders();
      httpHeaders.set("Content-Type", "application/x-www-form-urlencoded");
      httpHeaders.set("DPoP", dPoPProofWithoutNonce);

      HttpEntity<?> httpEntity = new HttpEntity<>(parameters, httpHeaders);

      restOperations.postForEntity(tokenUri, httpEntity, String.class);
    } catch (HttpClientErrorException ex) {
      if (ex.getStatusCode() == HttpStatus.BAD_REQUEST
          && ex.getResponseHeaders() != null
          && ex.getResponseBodyAsString().contains("use_dpop_nonce")) {
        String nonce = ex.getResponseHeaders().getFirst("DPoP-Nonce");
        try {
          return dPoPProofBuilder.createDPoPProof(
              HttpMethod.POST.name(), tokenUri.toString(), nonce, clientRegistration);
        } catch (JOSEException e) {
          throw new OAuth2AuthorizationException(new OAuth2Error("Failed to create DPoP proof"), e);
        }

      } else {
        throw new OAuth2AuthorizationException(
            new OAuth2Error("Failed to obtain nonce: " + ex.getResponseBodyAsString()));
      }
    } catch (JOSEException e) {
      throw new OAuth2AuthorizationException(new OAuth2Error("Failed to create DPoP proof"), e);
    }
    return null;
  }
}
