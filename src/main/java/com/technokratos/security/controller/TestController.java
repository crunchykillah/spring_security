package com.technokratos.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint. No authentication is required.";
    }

    @GetMapping("/private")
    public String privateEndpoint() {
        return "This is a private endpoint. Authentication is required.";
    }
}