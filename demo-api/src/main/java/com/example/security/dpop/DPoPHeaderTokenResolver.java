package com.example.security.dpop;

import org.springframework.security.oauth2.server.resource.web.HeaderBearerTokenResolver;

public class DPoPHeaderTokenResolver extends HeaderBearerTokenResolver {

  public DPoPHeaderTokenResolver() {
    super("DPoP");
  }
}
