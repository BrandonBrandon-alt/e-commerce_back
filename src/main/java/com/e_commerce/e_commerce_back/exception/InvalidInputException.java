package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Datos de entrada inválidos o validación fallida
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class InvalidInputException extends AuthException {
    public InvalidInputException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}