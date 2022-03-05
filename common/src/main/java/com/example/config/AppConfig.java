package com.example.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({OAuth2ClientHelseIDProperties.class,
        OAuth2ClientDetailProperties.class,
        OAuth2ClientResourceDetailProperties.class})
public class AppConfig {
}
