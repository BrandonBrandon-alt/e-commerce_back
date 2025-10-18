package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Cuenta temporalmente bloqueada (migración de AccountLockedException existente)
 */
@ResponseStatus(HttpStatus.LOCKED)
public class AccountLockedException extends AuthException {
    private final long remainingMinutes;
    
    public AccountLockedException(String message) {
        super(message, HttpStatus.LOCKED);
        this.remainingMinutes = 0;
    }
    
    public AccountLockedException(String message, long remainingMinutes) {
        super(message, HttpStatus.LOCKED);
        this.remainingMinutes = remainingMinutes;
    }
    
    public long getRemainingMinutes() {
        return remainingMinutes;
    }
}