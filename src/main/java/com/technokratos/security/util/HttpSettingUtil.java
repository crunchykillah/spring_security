package com.technokratos.security.util;

import com.technokratos.security.dto.TokenRequest;
import com.technokratos.security.security.exception.AuthenticationHeaderException;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.util.Optional;

import static com.technokratos.security.util.constants.SecurityConstants.BEARER;

@UtilityClass
@Slf4j
public class HttpSettingUtil {


    public String getTokenFromAuthorizationHeader(String authorizationHeader) {
        return Optional.ofNullable(authorizationHeader)
                .filter(authHeader -> !authHeader.trim().isEmpty())
                .map(authHeader -> {
                    if (authHeader.startsWith(BEARER)) {
                        return authHeader.substring(BEARER.length()).trim();
                    } else {
                        return null;
                    }
                })
                .orElse(null);
    }
    public TokenRequest getTokenFromValidatedAuthorizationHeader(String authorizationHeader) {

        if (authorizationHeader == null) {
            return null;
        }

        log.info("Loading user for Authorization header: {}", authorizationHeader);

        if (!authorizationHeader.startsWith(BEARER)) {
            throw new AuthenticationHeaderException("Invalid authentication scheme found in Authorization header");
        }

        String token = HttpSettingUtil.getTokenFromAuthorizationHeader(authorizationHeader);
        if (token == null) {
            throw new AuthenticationHeaderException("Authorization header token is empty");
        }

        return new TokenRequest(token);
    }
}
