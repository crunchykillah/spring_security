package com.technokratos.security.repository;

import com.technokratos.security.dto.Role;
import com.technokratos.security.security.userdetails.UserProfile;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class UserProfileRepositoryMock {

    private final PasswordEncoder passwordEncoder;

    public UserProfile findByLogin(String login) {
        if (login.equals("user1")) {
            return UserProfile.builder()
                    .username("user1")
                    .password(passwordEncoder.encode("password1"))
                    .name("User One")
                    .isAccountNonExpired(true)
                    .isAccountNonLocked(true)
                    .isCredentialsNonExpired(true)
                    .isEnabled(true)
                    .authorities(List.of(new SimpleGrantedAuthority(Role.USER.name())))
                    .build();
        } else {
            return null;
        }
    }
}
