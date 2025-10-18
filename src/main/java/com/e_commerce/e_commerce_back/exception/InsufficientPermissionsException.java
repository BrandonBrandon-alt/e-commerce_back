package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Usuario no tiene permisos suficientes
 */
@ResponseStatus(HttpStatus.FORBIDDEN)
public class InsufficientPermissionsException extends AuthException {
    public InsufficientPermissionsException(String message) {
        super(message, HttpStatus.FORBIDDEN);
    }
}