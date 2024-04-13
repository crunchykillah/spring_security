package com.technokratos.security.controller;

import com.technokratos.security.dto.AuthenticationRequest;
import com.technokratos.security.dto.AuthenticationResponse;
import com.technokratos.security.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthenticationResponse> signIn(@RequestBody AuthenticationRequest authenticationRequest) {
        AuthenticationResponse response = authenticationService.signIn(authenticationRequest);
        return ResponseEntity.ok(response);
    }
}