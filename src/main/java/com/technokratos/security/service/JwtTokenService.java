package com.technokratos.security.service;

import com.technokratos.security.dto.AccountResponse;
import com.technokratos.security.dto.TokenRequest;

public interface JwtTokenService {

    AccountResponse getUserInfoByToken(TokenRequest token);

    String generateAccessToken(AccountResponse accountResponse);
}
