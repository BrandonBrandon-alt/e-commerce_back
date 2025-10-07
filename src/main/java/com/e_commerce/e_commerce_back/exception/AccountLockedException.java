package com.e_commerce.e_commerce_back.exception;

public class AccountLockedException extends RuntimeException {
    
    public AccountLockedException(String message) {
        super(message);
    }
}
