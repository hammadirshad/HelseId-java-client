package com.example.security.dpop;

import com.example.config.DPoPProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;


@Slf4j
public class DPoPAuthenticationFilter extends OncePerRequestFilter {

  private final DPoPTokenValidator dPoPTokenValidator;

  public DPoPAuthenticationFilter(DPoPProperties dPoPCheckerProperties) {
    dPoPTokenValidator = new DPoPTokenValidator(dPoPCheckerProperties);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    try {
      dPoPTokenValidator.validate(request);
    } catch (Exception e) {
      log.error("DPoP token validation failed: {}", e.getMessage(), e);
      SecurityContextHolder.clearContext();
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " + e.getMessage());
      return;
    }

    chain.doFilter(request, response);
  }
}
