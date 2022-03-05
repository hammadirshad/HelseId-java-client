package com.example.service;

import com.example.config.OAuth2ClientHelseIDProperties;
import com.example.model.HelseOidcUser;
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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
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

    public HelseOidcUser createHelseIDBruker(OidcUser oidcUser) throws OAuth2AuthorizationException {

        final String nameAttributeKey =
                clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        return new HelseOidcUser(mapUserAuthorities(oidcUser), oidcUser.getIdToken(), oidcUser.getUserInfo(), nameAttributeKey);
    }

    /**
     * Create user authorities base on HelseID scope or from database
     */
    private Set<GrantedAuthority> mapUserAuthorities(OidcUser oidcUser) {
        OidcIdToken idToken = oidcUser.getIdToken();
        OidcUserInfo userInfo = oidcUser.getUserInfo();

        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_ACTIVE"));

        loadUserAuthorities(getPid(idToken, userInfo)).forEach(authority -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + authority));
        });

        oidcUser.getAuthorities()
                .forEach(grantedAuthority ->
                        authorities.add(new SimpleGrantedAuthority(grantedAuthority.getAuthority())));

        return new HashSet<>(authorities);
    }

    private String getPid(OidcIdToken idToken, OidcUserInfo userInfo) {
        if (userInfo != null && userInfo.getClaims().containsKey(HelseOidcUser.PID_Claim)) {
            return MethodsUtils.getStringOrNull(userInfo.getClaims().get(HelseOidcUser.PID_Claim));
        }
        if (idToken != null && idToken.getClaims().containsKey(HelseOidcUser.PID_Claim)) {
            return MethodsUtils.getStringOrNull(idToken.getClaims().get(HelseOidcUser.PID_Claim));
        }
        return null;
    }

    public List<SimpleGrantedAuthority> loadUserAuthorities(String pid) {
        return new ArrayList<>();
    }
}

