package com.example.security;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

@AllArgsConstructor
public class JwtScopeValidator implements OAuth2TokenValidator<Jwt> {

    private final String scope;

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if ((jwt.getClaims().get("scope") instanceof Collection authorities
                && castAuthoritiesToCollection(authorities).contains(scope))) {
            return OAuth2TokenValidatorResult.success();
        } else {
            OAuth2Error error = new OAuth2Error("invalid_token",
                    String.format("The required scope %s is missing", scope), null);
            return OAuth2TokenValidatorResult.failure(error);
        }
    }

    @SuppressWarnings("unchecked")
    private Collection<String> castAuthoritiesToCollection(Collection<?> authorities) {
        return (Collection<String>) authorities;
    }
}
