package com.example.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.io.Serializable;
import java.util.Set;

@Getter
@Setter
public class HelseIDBruker extends DefaultOidcUser implements Serializable {

    public static final String PID_Claim = "helseid://claims/identity/pid";
    public static final String SECURITY_LEVEL_CLAIM = "helseid://claims/identity/security_level";

    public HelseIDBruker(Set<GrantedAuthority> authorities,
                         OidcIdToken idToken,
                         OidcUserInfo userInfo,
                         String nameAttributeKey) {
        super(authorities, idToken, userInfo, nameAttributeKey);
    }

    public String getPid() {
        return this.getClaimAsString(PID_Claim);
    }

    public String getSecurityLevel() {
        return this.getClaimAsString(SECURITY_LEVEL_CLAIM);
    }
}

