package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Cuenta ya está activada
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class AccountAlreadyActiveException extends AuthException {
    public AccountAlreadyActiveException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}