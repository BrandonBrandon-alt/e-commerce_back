package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Email inválido o mal formado
 */
@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class InvalidEmailFormatException extends AuthException {
    public InvalidEmailFormatException(String message) {
        super(message, HttpStatus.UNPROCESSABLE_ENTITY);
    }
}