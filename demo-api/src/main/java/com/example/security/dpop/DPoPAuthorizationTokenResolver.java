package com.example.security.dpop;

import jakarta.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.StringUtils;

public final class DPoPAuthorizationTokenResolver implements BearerTokenResolver {

  private static final Pattern authorizationPattern =
      Pattern.compile("^DPoP (?<token>[a-zA-Z0-9-._~+/]+=*)$", Pattern.CASE_INSENSITIVE);

  private static final String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

  @Override
  public String resolve(final HttpServletRequest request) {
    return resolveFromAuthorizationHeader(request);
  }

  private String resolveFromAuthorizationHeader(HttpServletRequest request) {
    String authorization = request.getHeader(this.bearerTokenHeaderName);
    if (!StringUtils.startsWithIgnoreCase(authorization, "dpop")) {
      return null;
    }
    Matcher matcher = authorizationPattern.matcher(authorization);
    if (!matcher.matches()) {
      BearerTokenError error = BearerTokenErrors.invalidToken("DPoP token is malformed");
      throw new OAuth2AuthenticationException(error);
    }
    return matcher.group("token");
  }
}