package com.example.security.dpop.response;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.util.CollectionUtils;

public final class DPoPAccessTokenResponse {

  private DPoPAccessToken dPoPAccessToken;

  private Map<String, Object> additionalParameters;

  private DPoPAccessTokenResponse() {
  }

  public DPoPAccessToken getDPoPOAccessToken() {
    return this.dPoPAccessToken;
  }

  public Map<String, Object> getAdditionalParameters() {
    return this.additionalParameters;
  }

  public static Builder withToken(String tokenValue) {
    return new Builder(tokenValue);
  }

  public static final class Builder {

    private String tokenValue;

    private DPoPAccessToken.TokenType tokenType;

    private Instant issuedAt;

    private Instant expiresAt;

    private long expiresIn;

    private Set<String> scopes;

    private Map<String, Object> additionalParameters;

    private Builder(String tokenValue) {
      this.tokenValue = tokenValue;
    }

    public Builder tokenType(DPoPAccessToken.TokenType tokenType) {
      this.tokenType = tokenType;
      return this;
    }

    public Builder expiresIn(long expiresIn) {
      this.expiresIn = expiresIn;
      this.expiresAt = null;
      return this;
    }

    public Builder scopes(Set<String> scopes) {
      this.scopes = scopes;
      return this;
    }

    public Builder additionalParameters(
        Map<String, Object> additionalParameters) {
      this.additionalParameters = additionalParameters;
      return this;
    }

    public DPoPAccessTokenResponse build() {
      Instant issuedAt = getIssuedAt();
      Instant expiresAt = getExpiresAt();
      DPoPAccessTokenResponse accessTokenResponse = new DPoPAccessTokenResponse();
      accessTokenResponse.dPoPAccessToken =
          new DPoPAccessToken(this.tokenType, this.tokenValue, issuedAt, expiresAt, this.scopes);

      accessTokenResponse.additionalParameters =
          CollectionUtils.isEmpty(this.additionalParameters)
              ? new LinkedHashMap<>()
              : new LinkedHashMap<>(this.additionalParameters);
      return accessTokenResponse;
    }

    private Instant getIssuedAt() {
      if (this.issuedAt == null) {
        this.issuedAt = Instant.now();
      }
      return this.issuedAt;
    }

    private Instant getExpiresAt() {
      if (this.expiresAt == null) {
        Instant issuedAt = getIssuedAt();
        this.expiresAt =
            (this.expiresIn > 0) ? issuedAt.plusSeconds(this.expiresIn) : issuedAt.plusSeconds(1);
      }
      return this.expiresAt;
    }
  }
}
