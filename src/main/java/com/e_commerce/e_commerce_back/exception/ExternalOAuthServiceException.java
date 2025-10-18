package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Error al comunicarse con servicio OAuth externo
 */
@ResponseStatus(HttpStatus.BAD_GATEWAY)
public class ExternalOAuthServiceException extends AuthException {
    public ExternalOAuthServiceException(String message) {
        super(message, HttpStatus.BAD_GATEWAY);
    }
    
    public ExternalOAuthServiceException(String message, Throwable cause) {
        super(message, cause, HttpStatus.BAD_GATEWAY);
    }
}