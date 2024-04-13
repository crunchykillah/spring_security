package com.technokratos.security.security.provider;

import com.technokratos.security.dto.AccountResponse;
import com.technokratos.security.dto.TokenRequest;
import io.jsonwebtoken.Claims;

import java.util.Date;
import java.util.List;
import java.util.Map;

public interface JwtAccessTokenProvider {
    String generateAccessToken(String subject, Map<String, Object> data);

    boolean validateAccessToken(String accessToken, String subject);

    AccountResponse userInfoByToken(TokenRequest token);

    Claims parseAccessToken(String accessToken);

    List<String> getRolesFromAccessToken(String accessToken);

    Date getExpirationDateFromAccessToken(String accessToken);

    String getSubjectFromAccessToken(String accessToken);
}
