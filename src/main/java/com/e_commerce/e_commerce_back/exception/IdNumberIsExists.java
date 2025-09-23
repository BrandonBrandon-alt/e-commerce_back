package com.e_commerce.e_commerce_back.exception;

public class IdNumberIsExists extends RuntimeException {
    
    public IdNumberIsExists(String message) {
        super(message);
    }
}
