package com.example.config;

import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("spring.security.oauth2.resourceserver")
@Data
public class OAuth2ClientResourceDetailProperties {

    private List<Detail> detail;

    @Data
    public static class Detail {
        private String audience;

        private String scope;

    }
}

