package com.example.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Component
public class HelseIDJwtAuthenticationConverter implements
        Converter<Jwt, AbstractAuthenticationToken> {

    private static final String DEFAULT_AUTHORITY_PREFIX = "HelseID_SCOPE_";
    private static final String principalClaimName = JwtClaimNames.SUB;

    Converter<Jwt, Collection<GrantedAuthority>> scpGrupperingConverter = (jwt) -> {
        Map<String, Object> claims = new HashMap<>(jwt.getClaims());

        if (claims.get("scope") instanceof Collection authorities) {
            return castAuthoritiesToCollection(authorities).stream()
                    .map(String::strip)
                    .filter(s -> !s.isEmpty())
                    .map(s -> DEFAULT_AUTHORITY_PREFIX + s)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        if (claims.get("scp") instanceof String scp) {
            return Stream.of(scp.split(","))
                    .map(String::strip)
                    .filter(s -> !s.isEmpty())
                    .map(s -> DEFAULT_AUTHORITY_PREFIX + s)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }
        return new ArrayList<>();
    };


    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String principalClaimValue = jwt.getClaimAsString(principalClaimName);

        return new JwtAuthenticationToken(jwt, scpGrupperingConverter.convert(jwt),
                principalClaimValue);
    }

    @SuppressWarnings("unchecked")
    private Collection<String> castAuthoritiesToCollection(Collection authorities) {
        return (Collection<String>) authorities;
    }
}

