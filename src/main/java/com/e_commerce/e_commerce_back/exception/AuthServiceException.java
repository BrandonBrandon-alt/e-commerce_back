package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Error interno del servidor de autenticación
 */
@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class AuthServiceException extends AuthException {
    public AuthServiceException(String message) {
        super(message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    public AuthServiceException(String message, Throwable cause) {
        super(message, cause, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
