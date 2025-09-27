package com.e_commerce.e_commerce_back.exception;

public class PasswordsDoNotMatch extends RuntimeException {
    public PasswordsDoNotMatch(String message) {
        super(message);
    }
}
