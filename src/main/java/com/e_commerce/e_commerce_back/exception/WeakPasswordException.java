package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Contraseña no cumple requisitos de seguridad
 */
@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class WeakPasswordException extends AuthException {
    public WeakPasswordException(String message) {
        super(message, HttpStatus.UNPROCESSABLE_ENTITY);
    }
}