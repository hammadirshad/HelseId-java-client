package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties("spring.security.oauth2.client.post-logout")
@Data
public class OAuth2ClientLogoutProperties {

    private final Map<String, Registration> registration = new HashMap<>();

    @Data
    public static class Registration {

        /**
         * The the client may also send to uri id sign-out pass
         */
        private String redirectUri;

        /**
         * The end session endpoint can be used to trigger single sign-out.
         */
        private String endSessionEndpoint;
    }
}
