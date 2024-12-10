package com.example.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecureResource {

  @RequestMapping("/api/secured")
  public ResponseEntity<?> secured() {
    return new ResponseEntity<>("{\"message\",\"secured\"}", HttpStatus.OK);
  }

  @RequestMapping("/api/client-name")
  public ResponseEntity<?> secureEndpoint(@AuthenticationPrincipal Jwt user) {
    String clinetName = (String) user.getClaims().get("helseid://claims/client/client_name");
    String clinetOrgnr = (String) user.getClaims().get("helseid://claims/client/claims/orgnr_parent");
    return new ResponseEntity<>(clinetName + "[" + clinetOrgnr + "]", HttpStatus.OK);
  }

  @RequestMapping("/api/token-info")
  public ResponseEntity<?> tokenInfo(@AuthenticationPrincipal Jwt user) {
    return new ResponseEntity<>(user, HttpStatus.OK);
  }
}
