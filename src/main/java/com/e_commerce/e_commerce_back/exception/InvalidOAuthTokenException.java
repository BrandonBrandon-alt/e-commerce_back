
package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidOAuthTokenException extends AuthException {
    public InvalidOAuthTokenException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }

    public InvalidOAuthTokenException(String message, Throwable cause) {
        super(message, cause, HttpStatus.UNAUTHORIZED);
    }
}