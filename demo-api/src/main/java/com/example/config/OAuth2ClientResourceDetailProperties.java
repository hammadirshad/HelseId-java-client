package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("spring.security.oauth2.resourceserver.detail")
@Data
public class OAuth2ClientResourceDetailProperties {

    private String audience;

    private String scope;
}

