package com.technokratos.security.security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class AuthenticationHeaderException extends AuthenticationException {

    public AuthenticationHeaderException(String msg) {
        super(msg);
    }
}