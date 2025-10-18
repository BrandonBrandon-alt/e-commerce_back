package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Demasiados intentos (rate limiting)
 */
@ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
public class TooManyAttemptsException extends AuthException {
    private final long retryAfterSeconds;
    
    public TooManyAttemptsException(String message) {
        super(message, HttpStatus.TOO_MANY_REQUESTS);
        this.retryAfterSeconds = 3600; // 1 hora por defecto
    }
    
    public TooManyAttemptsException(String message, long retryAfterSeconds) {
        super(message, HttpStatus.TOO_MANY_REQUESTS);
        this.retryAfterSeconds = retryAfterSeconds;
    }
    
    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}