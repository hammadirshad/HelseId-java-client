package com.example.controller;

import com.example.model.HelseOidcUser;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TokenResource {

    @RequestMapping("/api/token-info")
    public ResponseEntity<?> brukerInfo(@AuthenticationPrincipal HelseOidcUser user) {
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
}
