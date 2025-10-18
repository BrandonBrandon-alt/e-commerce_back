package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Sesión inválida o expirada
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidSessionException extends AuthException {
    public InvalidSessionException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}