package com.example.security.dpop.response;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

public class DPoPAccessToken extends AbstractOAuth2Token {

  private final TokenType tokenType;

  private final Set<String> scopes;

  public DPoPAccessToken(
      TokenType tokenType,
      String tokenValue,
      Instant issuedAt,
      Instant expiresAt,
      Set<String> scopes) {
    super(tokenValue, issuedAt, expiresAt);
    Assert.notNull(tokenType, "tokenType cannot be null");
    this.tokenType = tokenType;
    this.scopes = Collections.unmodifiableSet((scopes != null) ? scopes : Collections.emptySet());
  }

  public TokenType getTokenType() {
    return this.tokenType;
  }

  public Set<String> getScopes() {
    return this.scopes;
  }

  public static final class TokenType implements Serializable {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    public static final TokenType DPOP = new TokenType("DPoP");

    private final String value;

    private TokenType(String value) {
      Assert.hasText(value, "value cannot be empty");
      this.value = value;
    }

    public String getValue() {
      return this.value;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (obj == null || this.getClass() != obj.getClass()) {
        return false;
      }
      TokenType that = (TokenType) obj;
      return this.getValue().equalsIgnoreCase(that.getValue());
    }

    @Override
    public int hashCode() {
      return this.getValue().hashCode();
    }

  }
}
