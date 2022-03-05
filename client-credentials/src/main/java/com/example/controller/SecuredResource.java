package com.example.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredResource {

    @RequestMapping("/api/secured")
    public ResponseEntity<?> secured() {
        return new ResponseEntity<>("{\"message\",\"secured\"}", HttpStatus.OK);
    }
}
