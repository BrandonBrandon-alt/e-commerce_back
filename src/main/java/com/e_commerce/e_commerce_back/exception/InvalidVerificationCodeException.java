package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Código de verificación inválido o expirado
 */
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidVerificationCodeException extends AuthException {
    public InvalidVerificationCodeException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}