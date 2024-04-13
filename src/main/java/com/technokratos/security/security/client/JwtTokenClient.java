package com.technokratos.security.security.client;

import com.technokratos.security.dto.AccountResponse;
import com.technokratos.security.dto.TokenRequest;
import com.technokratos.security.service.JwtTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwtTokenClient {

    private final JwtTokenService jwtTokenService;

    public AccountResponse userInfoByToken(TokenRequest token) {
        return jwtTokenService.getUserInfoByToken(token);
    }

}
