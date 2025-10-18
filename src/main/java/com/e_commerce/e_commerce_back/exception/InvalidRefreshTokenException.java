package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Refresh token inválido
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidRefreshTokenException extends AuthException {
    public InvalidRefreshTokenException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}