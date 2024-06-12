package com.example.security.dpop.client;

import com.example.security.dpop.response.DPoPAccessTokenResponse;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;

@FunctionalInterface
public interface DPoPAccessTokenResponseClient<T extends AbstractOAuth2AuthorizationGrantRequest> {


  DPoPAccessTokenResponse getTokenResponse(T authorizationGrantRequest);

}


