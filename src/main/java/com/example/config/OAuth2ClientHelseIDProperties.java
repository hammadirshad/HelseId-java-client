package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("helseid")
public class OAuth2ClientHelseIDProperties {

    private STS sts = new STS();

    private Registration registrationName = new Registration();

    @Data
    public static class STS {

        private String uri;
    }

    @Data
    public static class Registration {

        private String login;

        private String ehelse;

        private String machine;
    }
}
