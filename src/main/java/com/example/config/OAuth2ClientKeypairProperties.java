package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties("spring.security.oauth2.client.jwt")
@Data
public class OAuth2ClientKeypairProperties {

    private final Map<String, Registration> registration = new HashMap<>();

    @Data
    public static class Registration {

        private String privateKey;
    }
}

