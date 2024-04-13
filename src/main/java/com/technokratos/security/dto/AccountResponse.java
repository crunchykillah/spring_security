package com.technokratos.security.dto;

import java.util.UUID;

public record AccountResponse(
        UUID id,
        String email,
        String login,
        String name,
        char[] password,
        boolean isAccountNonExpired,
        boolean isAccountNonLocked,
        Role role
) {
}