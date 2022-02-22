package com.example.security;

import com.example.config.OAuth2ClientHelseIDProperties;
import com.example.model.HelseIDBruker;
import com.example.utils.MethodsUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
public class OidcHelseIDBrukerService extends OidcUserService {

    private final ClientRegistration clientRegistration;

    public OidcHelseIDBrukerService(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2ClientHelseIDProperties helseIDProperties) {
        clientRegistration =
                clientRegistrationRepository.findByRegistrationId(
                        helseIDProperties.getRegistrationName().getLogin());
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        try {
            return createHelseIDBruker(oidcUser);
        } catch (Exception e) {
            log.error(e.getMessage());
            return oidcUser;
        }
    }

    public HelseIDBruker createHelseIDBruker(OidcUser oidcUser) throws OAuth2AuthorizationException {
        OidcIdToken idToken = oidcUser.getIdToken();
        OidcUserInfo userInfo = oidcUser.getUserInfo();

        final String nameAttributeKey =
                clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        String pid = getPid(idToken, userInfo);

        Set<GrantedAuthority> mappedAuthorities = getMappedAuthorities();

        return new HelseIDBruker(mappedAuthorities, idToken, userInfo, nameAttributeKey);
    }

    private String getPid(OidcIdToken idToken, OidcUserInfo userInfo) {
        if (userInfo != null && userInfo.getClaims().containsKey(HelseIDBruker.PID_Claim)) {
            return MethodsUtils.getStringOrNull(userInfo.getClaims().get(HelseIDBruker.PID_Claim));
        }
        if (idToken != null && idToken.getClaims().containsKey(HelseIDBruker.PID_Claim)) {
            return MethodsUtils.getStringOrNull(idToken.getClaims().get(HelseIDBruker.PID_Claim));
        }
        return null;
    }

    public Set<GrantedAuthority> getMappedAuthorities() {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ACTIVE"));
        return new HashSet<>(authorities);
    }
}

