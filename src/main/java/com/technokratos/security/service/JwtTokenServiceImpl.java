package com.technokratos.security.service;

import com.technokratos.security.dto.AccountResponse;
import com.technokratos.security.dto.TokenRequest;
import com.technokratos.security.security.provider.JwtAccessTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;

import static com.technokratos.security.util.constants.SecurityConstants.ROLE;

@Service
@RequiredArgsConstructor
public class JwtTokenServiceImpl implements JwtTokenService {

    private final JwtAccessTokenProvider jwtAccessTokenProvider;

    @Override
    public AccountResponse getUserInfoByToken(TokenRequest token) {
        return jwtAccessTokenProvider.userInfoByToken(token);
    }

    @Override
    public String generateAccessToken(AccountResponse accountResponse) {
        return jwtAccessTokenProvider.generateAccessToken(
                accountResponse.login(),
                Collections.singletonMap(ROLE, accountResponse.role())
        );
    }
}