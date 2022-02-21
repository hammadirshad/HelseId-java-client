package com.example.controller;

import com.example.model.HelseIDBruker;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@RestController
@RequiredArgsConstructor
public class IndexResource {

    @RequestMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> index(
            @AuthenticationPrincipal HelseIDBruker helseIDBruker, HttpServletRequest httpServletRequest) {

        String message;
        if (helseIDBruker != null) {
            message = String.format(
                    """
                            {"login": "%s"}
                            """,
                    (helseIDBruker.getFullName() != null
                            ? "Velkommen, " + helseIDBruker.getFullName()
                            : "Profile does not exists"));

        } else {
            message = String.format(
                    """
                            {"login": "%s"}
                            """, "/api/bruker-info");
        }
        return new ResponseEntity<>(message, HttpStatus.OK);
    }

    @RequestMapping("/api/bruker-info")
    public ResponseEntity<?> brukerInfo(@AuthenticationPrincipal HelseIDBruker user) {
        return new ResponseEntity<>(user, HttpStatus.OK);
    }
}
