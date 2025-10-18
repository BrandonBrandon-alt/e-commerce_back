package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Número de identificación ya registrado (migración de IdNumberIsExists)
 */
@ResponseStatus(HttpStatus.CONFLICT)
public class IdNumberAlreadyExistsException extends AuthException {
    public IdNumberAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }
}
