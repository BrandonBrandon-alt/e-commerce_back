

package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class InvalidCredentialsException extends AuthException {
    private final int remainingAttempts;
    
    public InvalidCredentialsException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
        this.remainingAttempts = 0;
    }
    
    public InvalidCredentialsException(String message, int remainingAttempts) {
        super(message, HttpStatus.UNAUTHORIZED);
        this.remainingAttempts = remainingAttempts;
    }
    
    public int getRemainingAttempts() {
        return remainingAttempts;
    }
}