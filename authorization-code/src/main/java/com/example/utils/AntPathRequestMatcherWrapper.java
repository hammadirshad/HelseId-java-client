package com.example.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;



public abstract class AntPathRequestMatcherWrapper implements RequestMatcher {

    private final AntPathRequestMatcher delegate;

    public AntPathRequestMatcherWrapper(String pattern) {
        this.delegate = new AntPathRequestMatcher(pattern);
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (precondition(request)) {
            return delegate.matches(request);
        }
        return false;
    }

    protected abstract boolean precondition(HttpServletRequest request);

}

