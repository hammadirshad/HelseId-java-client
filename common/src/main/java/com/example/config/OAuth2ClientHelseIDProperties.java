package com.example.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("helseid")
public class OAuth2ClientHelseIDProperties {

  private STS sts = new STS();

  @Data
  public static class STS {

    private String uri;
  }


}
