package com.example.security.dpop.client;

import com.example.security.dpop.response.DPoPAccessTokenResponse;
import com.example.security.dpop.response.DPoPAccessTokenResponseConverter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

public class DPoPAccessTokenResponseHttpMessageConverter
    extends AbstractHttpMessageConverter<DPoPAccessTokenResponse> {

  private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

  private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP =
      new ParameterizedTypeReference<>() {
      };

  private final GenericHttpMessageConverter<Object> jsonMessageConverter =
      HttpMessageConverters.getJsonMessageConverter();

  private final Converter<Map<String, Object>, DPoPAccessTokenResponse> accessTokenResponseConverter =
      new DPoPAccessTokenResponseConverter();

  public DPoPAccessTokenResponseHttpMessageConverter() {
    super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
  }

  @Override
  protected boolean supports(Class<?> clazz) {
    return DPoPAccessTokenResponse.class.isAssignableFrom(clazz);
  }

  @Override
  @SuppressWarnings("unchecked")
  protected DPoPAccessTokenResponse readInternal(
      Class<? extends DPoPAccessTokenResponse> clazz, HttpInputMessage inputMessage)
      throws HttpMessageNotReadableException {
    try {
      Map<String, Object> tokenResponseParameters =
          (Map<String, Object>)
              this.jsonMessageConverter.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
      return this.accessTokenResponseConverter.convert(tokenResponseParameters);
    } catch (Exception ex) {
      throw new HttpMessageNotReadableException(
          "An error occurred reading the OAuth 2.0 Access Token Response: " + ex.getMessage(),
          ex,
          inputMessage);
    }
  }

  @Override
  protected void writeInternal(
      DPoPAccessTokenResponse tokenResponse, HttpOutputMessage outputMessage)
      throws HttpMessageNotWritableException {
    try {
      Map<String, Object> tokenResponseParameters = this.convert(tokenResponse);
      this.jsonMessageConverter.write(
          tokenResponseParameters,
          STRING_OBJECT_MAP.getType(),
          MediaType.APPLICATION_JSON,
          outputMessage);
    } catch (Exception ex) {
      throw new HttpMessageNotWritableException(
          "An error occurred writing the OAuth 2.0 Access Token Response: " + ex.getMessage(), ex);
    }
  }

  public Map<String, Object> convert(DPoPAccessTokenResponse tokenResponse) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(
        OAuth2ParameterNames.ACCESS_TOKEN, tokenResponse.getDPoPOAccessToken().getTokenValue());
    parameters.put(
        OAuth2ParameterNames.TOKEN_TYPE,
        tokenResponse.getDPoPOAccessToken().getTokenType().getValue());

    if (tokenResponse.getDPoPOAccessToken().getExpiresAt() != null) {
      parameters.put(
          OAuth2ParameterNames.EXPIRES_IN,
          ChronoUnit.SECONDS.between(
              Instant.now(), tokenResponse.getDPoPOAccessToken().getExpiresAt()));
    } else {
      parameters.put(OAuth2ParameterNames.EXPIRES_IN, -1);
    }

    if (!CollectionUtils.isEmpty(tokenResponse.getDPoPOAccessToken().getScopes())) {
      parameters.put(
          OAuth2ParameterNames.SCOPE,
          StringUtils.collectionToDelimitedString(
              tokenResponse.getDPoPOAccessToken().getScopes(), " "));
    }

    if (!CollectionUtils.isEmpty(tokenResponse.getAdditionalParameters())) {
      parameters.putAll(tokenResponse.getAdditionalParameters());
    }
    return parameters;
  }
}
