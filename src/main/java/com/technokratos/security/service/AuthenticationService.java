package com.technokratos.security.service;

import com.technokratos.security.dto.AuthenticationRequest;
import com.technokratos.security.dto.AuthenticationResponse;
import com.technokratos.security.security.provider.JwtAccessTokenProvider;
import com.technokratos.security.security.userdetails.UserProfile;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserProfileService userService;
    private final JwtAccessTokenProvider jwtAccessTokenProvider;

    public AuthenticationResponse signIn(final AuthenticationRequest authenticationRequest) {
        String login = authenticationRequest.login();
        UserProfile user = userService.getUserByLogin(login);
        String presentedPassword = authenticationRequest.password();
        String currentPassword = user.getPassword();
        checkPassword(presentedPassword, currentPassword);

        String tokenId = Base64.getEncoder().encodeToString((user.getId() + "_" + user.getUsername()).getBytes());

        return new AuthenticationResponse(createAccessToken(user, tokenId));
    }

    private String createAccessToken(final UserProfile user, final String tokenId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId());
        claims.put("login", user.getUsername());
        claims.put("tokenId", tokenId);
        claims.put("role", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()));

        String accessToken = jwtAccessTokenProvider.generateAccessToken(user.getUsername(), claims);

        return accessToken;
    }
    private void checkPassword(String presentedPassword, String currentPassword) {
        if (!passwordEncoder.matches(presentedPassword, currentPassword)) {
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}
