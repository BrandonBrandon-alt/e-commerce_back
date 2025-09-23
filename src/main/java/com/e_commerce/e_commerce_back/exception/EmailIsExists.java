package com.e_commerce.e_commerce_back.exception;

public class EmailIsExists extends RuntimeException {
    
    public EmailIsExists(String message) {
        super(message);
    }
}
