package com.technokratos.security.dto;

public record AuthenticationRequest(
        String login,
        String password
) {
}