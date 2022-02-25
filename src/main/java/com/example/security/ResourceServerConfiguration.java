package com.example.security;


import com.example.service.HelseIDJwtAuthenticationConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Order(3)
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ResourceServerConfiguration extends WebSecurityConfigurerAdapter {

    public final HelseIDJwtAuthenticationConverter jwtAuthenticationConverter;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.requestMatcher(CommonWebSecurityConfigurator.resourceServerRequestMatcher())
                .authorizeRequests(CommonWebSecurityConfigurator::configureAuthorizeRequests)
                .sessionManagement(CommonWebSecurityConfigurator::configurerSessionManagement)
                .headers(headers -> headers.frameOptions().disable())
                .oauth2ResourceServer(
                        oauth2ResourceServer ->
                                oauth2ResourceServer.jwt().jwtAuthenticationConverter(jwtAuthenticationConverter));
    }
}
