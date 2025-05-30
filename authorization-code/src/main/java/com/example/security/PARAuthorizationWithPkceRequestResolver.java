package com.example.security;

import com.example.config.OAuth2ClientDetailProperties;
import com.example.config.OAuth2ClientDetailProperties.Registration;
import com.example.service.JwtClientAssertionParametersService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

public class PARAuthorizationWithPkceRequestResolver implements OAuth2AuthorizationRequestResolver {

  private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
  private static final char PATH_DELIMITER = '/';
  private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
      new Base64StringKeyGenerator(Base64.getUrlEncoder());
  private final ClientRegistrationRepository clientRegistrationRepository;
  private final PathPatternRequestMatcher authorizationRequestMatcher;

  private final JwtClientAssertionParametersService jwtClientAssertionParametersService;
  private final Map<String, OAuth2ClientDetailProperties.Registration> registrations;

  private final RestClient restClient =
      RestClient.builder()
          .messageConverters(
              (messageConverters) -> {
                messageConverters.clear();
                messageConverters.add(new FormHttpMessageConverter());
                messageConverters.add(new OAuth2AccessTokenResponseHttpMessageConverter());
                messageConverters.add(new MappingJackson2HttpMessageConverter());
              })
          .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
          .build();

  public PARAuthorizationWithPkceRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository,
      Map<String, OAuth2ClientDetailProperties.Registration> registrations,
      String authorizationRequestBaseUri) {
    Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
    Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.authorizationRequestMatcher =
        PathPatternRequestMatcher.withDefaults()
            .matcher(authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");

    this.registrations = registrations;
    jwtClientAssertionParametersService = new JwtClientAssertionParametersService(registrations);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    String registrationId = resolveRegistrationId(request);
    if (registrationId == null) {
      return null;
    }
    String redirectUriAction = getAction(request, "login");
    return resolve(request, registrationId, redirectUriAction);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
    if (registrationId == null) {
      return null;
    }
    String redirectUriAction = getAction(request, "authorize");
    return resolve(request, registrationId, redirectUriAction);
  }

  private OAuth2AuthorizationRequest resolve(
      HttpServletRequest request, String registrationId, String redirectUriAction) {
    if (registrationId == null) {
      return null;
    }
    ClientRegistration clientRegistration =
        this.clientRegistrationRepository.findByRegistrationId(registrationId);
    if (clientRegistration == null) {
      throw new IllegalArgumentException("Invalid Client Registration with Id: " + registrationId);
    }

    String redirectUri = expandRedirectUri(request, clientRegistration, redirectUriAction);
    String state = DEFAULT_STATE_GENERATOR.generateKey();
    Map<String, Object> pkceParameters = buildPkceParameters(clientRegistration);
    String parRequestUri =
        sendParRequest(redirectUri, state, clientRegistration, pkceParameters).request_uri;

    return buildOAuth2AuthorizationRequest(
        pkceParameters, clientRegistration, redirectUri, state, parRequestUri);
  }

  private OAuth2AuthorizationRequest buildOAuth2AuthorizationRequest(
      Map<String, Object> pkceParameters,
      ClientRegistration clientRegistration,
      String redirectUri,
      String state,
      String parRequestUri) {
    String codeVerifier = pkceParameters.get(PkceParameterNames.CODE_VERIFIER).toString();

    String authorizationEndpoint =
        clientRegistration
            .getProviderDetails()
            .getConfigurationMetadata()
            .get("authorization_endpoint")
            .toString();

    String authorizationRequestUri =
        getAuthorizationRequestUri(
            clientRegistration.getClientId(), authorizationEndpoint, parRequestUri);

    return OAuth2AuthorizationRequest.authorizationCode()
        .attributes(
            (attrs) -> {
              attrs.put(
                  OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId());
              attrs.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
            })
        .redirectUri(redirectUri)
        .clientId(clientRegistration.getClientId())
        .scope(OidcScopes.OPENID)
        .authorizationUri(authorizationEndpoint)
        .authorizationRequestUri(authorizationRequestUri)
        .state(state)
        .build();
  }

  private String getAuthorizationRequestUri(
      String clientId, String authorizationEndpoint, String parRequestUri) {

    MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
    queryParams.put("request_uri", List.of(parRequestUri));
    queryParams.put(OAuth2ParameterNames.CLIENT_ID, List.of(clientId));

    DefaultUriBuilderFactory uriBuilderFactory = new DefaultUriBuilderFactory();
    uriBuilderFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.NONE);
    UriBuilder uriBuilder =
        uriBuilderFactory.uriString(authorizationEndpoint).queryParams(queryParams);
    return uriBuilder.build().toString();
  }

  public ParResponse sendParRequest(
      String redirectUri,
      String state,
      ClientRegistration clientRegistration,
      Map<String, Object> pkceParameters) {
    String parEndpoint =
        clientRegistration
            .getProviderDetails()
            .getConfigurationMetadata()
            .get("pushed_authorization_request_endpoint")
            .toString();

    String codeChallengeMethod =
        pkceParameters.get(PkceParameterNames.CODE_CHALLENGE_METHOD).toString();
    String codeChallenge = pkceParameters.get(PkceParameterNames.CODE_CHALLENGE).toString();

    MultiValueMap<String, String> assertionParameters =
        jwtClientAssertionParametersService.buildClientAssertionParameters(clientRegistration);

    String clientAssertionType =
        assertionParameters.get(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE).getFirst();
    String clientAssertion =
        assertionParameters.get(OAuth2ParameterNames.CLIENT_ASSERTION).getFirst();

    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
    body.add(OAuth2ParameterNames.SCOPE, String.join(" ", clientRegistration.getScopes()));
    body.add(OAuth2ParameterNames.REDIRECT_URI, redirectUri);
    body.add(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2ParameterNames.CODE);
    body.add(OAuth2ParameterNames.STATE, state);
    body.add(PkceParameterNames.CODE_CHALLENGE_METHOD, codeChallengeMethod);
    body.add(PkceParameterNames.CODE_CHALLENGE, codeChallenge);

    body.add(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE, clientAssertionType);
    body.add(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);

    Registration registration = registrations.get(clientRegistration.getRegistrationId());
    if (registration != null) {
      if (registration.getAcrValues() != null && !registration.getAcrValues().isEmpty()) {
        body.add("acr_values", registration.getAcrValues());
      }
      if (registration.getPrompt() != null && !registration.getPrompt().isEmpty()) {
        body.add("prompt", registration.getPrompt());
      }
    }

    ResponseEntity<ParResponse> response =
        restClient
            .post()
            .uri(parEndpoint)
            .body(body)
            .headers(
                httpHeaders -> httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED))
            .retrieve()
            .toEntity(ParResponse.class);

    if (response.hasBody()) {
      return response.getBody();
    }
    return null;
  }

  private Map<String, Object> buildPkceParameters(ClientRegistration clientRegistration) {
    Builder builder =
        OAuth2AuthorizationRequest.authorizationCode()
            .clientId(clientRegistration.getClientId())
            .authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri());

    OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
    OAuth2AuthorizationRequest build = builder.build();
    Map<String, Object> additionalParameters = new HashMap<>(build.getAdditionalParameters());
    additionalParameters.put(
        PkceParameterNames.CODE_VERIFIER, build.getAttribute(PkceParameterNames.CODE_VERIFIER));
    return additionalParameters;
  }

  public static class ParResponse {

    public String request_uri;
    public String expires_in;
  }

  private String getAction(HttpServletRequest request, String defaultAction) {
    String action = request.getParameter("action");
    if (action == null) {
      return defaultAction;
    }
    return action;
  }

  private String resolveRegistrationId(HttpServletRequest request) {
    if (this.authorizationRequestMatcher.matches(request)) {
      return this.authorizationRequestMatcher
          .matcher(request)
          .getVariables()
          .get(REGISTRATION_ID_URI_VARIABLE_NAME);
    }
    return null;
  }

  private String expandRedirectUri(
      HttpServletRequest request, ClientRegistration clientRegistration, String action) {
    Map<String, String> uriVariables = new HashMap<>();
    uriVariables.put("registrationId", clientRegistration.getRegistrationId());
    // @formatter:off
    UriComponents uriComponents =
        UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
            .replacePath(request.getContextPath())
            .replaceQuery(null)
            .fragment(null)
            .build();
    // @formatter:on
    String scheme = uriComponents.getScheme();
    uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
    String host = uriComponents.getHost();
    uriVariables.put("baseHost", (host != null) ? host : "");
    // following logic is based on HierarchicalUriComponents#toUriString()
    int port = uriComponents.getPort();
    uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
    String path = uriComponents.getPath();
    if (StringUtils.hasLength(path)) {
      if (path.charAt(0) != PATH_DELIMITER) {
        path = PATH_DELIMITER + path;
      }
    }
    uriVariables.put("basePath", (path != null) ? path : "");
    uriVariables.put("baseUrl", uriComponents.toUriString());
    uriVariables.put("action", (action != null) ? action : "");
    return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUri())
        .buildAndExpand(uriVariables)
        .toUriString();
  }
}
