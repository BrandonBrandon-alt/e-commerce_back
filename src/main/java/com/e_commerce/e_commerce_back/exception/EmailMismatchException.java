package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Los emails no coinciden
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class EmailMismatchException extends AuthException {
    public EmailMismatchException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
}