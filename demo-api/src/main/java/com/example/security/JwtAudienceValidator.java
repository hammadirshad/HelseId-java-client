package com.example.security;

import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

@AllArgsConstructor
public class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final String audience;

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (jwt.getAudience().contains(audience)) {
            return OAuth2TokenValidatorResult.success();
        } else {
            OAuth2Error error = new OAuth2Error("invalid_token",
                    String.format("The required audience %s is missing", audience), null);
            return OAuth2TokenValidatorResult.failure(error);
        }
    }
}
