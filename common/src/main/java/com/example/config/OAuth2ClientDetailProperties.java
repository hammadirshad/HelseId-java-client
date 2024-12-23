package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties("spring.security.oauth2.client.detail")
@Data
public class OAuth2ClientDetailProperties {

    private final Map<String, Registration> registration = new HashMap<>();

    public Registration getRegistration(String key) {
        return registration.get(key);
    }

    @Data
    public static class Registration {

        private String baseRedirectUri;

        /**
         * The the client may also send to uri id sign-out pass
         */
        private String postLogoutRedirectUri;

        /**
         * The end session endpoint can be used to trigger single sign-out.
         */
        private String endSessionEndpoint;

        private String privateKey;

        private String keyId;

        private String orgNumber;

        private String acrValues;

        private String prompt;
    }
}
