package com.example.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexResource {

  @RequestMapping("/")
  public ResponseEntity<?> secured() {
    return new ResponseEntity<>("{\"message\",\"not-secured\"}", HttpStatus.OK);
  }

}
