package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Token JWT inválido o expirado
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidTokenException extends AuthException {
    public InvalidTokenException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}