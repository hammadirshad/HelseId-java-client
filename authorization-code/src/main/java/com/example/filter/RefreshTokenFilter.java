package com.example.filter;

import com.example.security.HelseIDAuthorizationCodeTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshTokenFilter extends OncePerRequestFilter {
    private final HelseIDAuthorizationCodeTokenService helseIDAuthorizationCodeTokenService;

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
        HttpServletResponse httpServletResponse, FilterChain filterChain) {

        final String pathWithoutContextPath =
            new UrlPathHelper().getPathWithinApplication(httpServletRequest);
        if (pathWithoutContextPath.equals("/api") || pathWithoutContextPath.startsWith("/api/")) {
            refreshToken(httpServletRequest, httpServletResponse);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void refreshToken(HttpServletRequest httpServletRequest,
        HttpServletResponse httpServletResponse) {
        try {
            helseIDAuthorizationCodeTokenService.getAccessTokenOrRefresh(httpServletRequest,
                httpServletResponse, true);
        } catch (Exception e) {
            log.error("Feil i refresh token filter: {}", e.getMessage(), e);
        }
    }
}