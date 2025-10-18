package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Las contraseñas no coinciden
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class PasswordMismatchException extends AuthException {
    public PasswordMismatchException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}