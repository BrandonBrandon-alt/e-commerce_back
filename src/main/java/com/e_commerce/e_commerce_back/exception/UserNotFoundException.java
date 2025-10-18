package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Usuario no encontrado
 */
@ResponseStatus(HttpStatus.NOT_FOUND)
public class UserNotFoundException extends AuthException {
    public UserNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
}