package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;

public abstract class AuthException extends RuntimeException {
    private final HttpStatus status;

    protected AuthException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    protected AuthException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
