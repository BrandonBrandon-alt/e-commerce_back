package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Error al enviar email
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class EmailServiceException extends AuthException {
    public EmailServiceException(String message) {
        super(message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    public EmailServiceException(String message, Throwable cause) {
        super(message, cause, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}