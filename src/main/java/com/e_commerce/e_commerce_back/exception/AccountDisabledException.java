package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Cuenta deshabilitada por administrador
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class AccountDisabledException extends AuthException {
    public AccountDisabledException(String message) {
        super(message, HttpStatus.FORBIDDEN);
    }
}