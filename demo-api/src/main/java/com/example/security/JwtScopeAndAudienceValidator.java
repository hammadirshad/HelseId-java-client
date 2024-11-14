package com.example.security;


import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import com.example.config.OAuth2ClientResourceDetailProperties;

@AllArgsConstructor
public class JwtScopeAndAudienceValidator implements OAuth2TokenValidator<Jwt> {

  private final List<OAuth2ClientResourceDetailProperties.Detail> details;

  public OAuth2TokenValidatorResult validate(Jwt jwt) {
    for (OAuth2ClientResourceDetailProperties.Detail detail : details) {

      if (jwt.getAudience().contains(detail.getAudience())) {
        if ((jwt.getClaims().get("scope") instanceof Collection<?> authorities
            && castAuthoritiesToCollection(authorities).stream()
            .anyMatch(scope -> detail.getScope().equals(scope)))) {
          return OAuth2TokenValidatorResult.success();
        } else {
          OAuth2Error error =
              new OAuth2Error(
                  "invalid_token",
                  String.format("The required scope %s is missing", detail.getScope()),
                  null);
          return OAuth2TokenValidatorResult.failure(error);
        }
      }
    }
    String audience =
        details.stream()
            .map(OAuth2ClientResourceDetailProperties.Detail::getAudience)
            .collect(Collectors.joining(", "));

    OAuth2Error error =
        new OAuth2Error(
            "invalid_token", String.format("The required audience %s is missing", audience), null);
    return OAuth2TokenValidatorResult.failure(error);
  }

  @SuppressWarnings("unchecked")
  private Collection<String> castAuthoritiesToCollection(Collection<?> authorities) {
    return (Collection<String>) authorities;
  }
}
