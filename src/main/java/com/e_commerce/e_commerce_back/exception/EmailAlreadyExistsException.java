package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Email ya registrado (migración de EmailIsExists)
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class EmailAlreadyExistsException extends AuthException {
    public EmailAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}