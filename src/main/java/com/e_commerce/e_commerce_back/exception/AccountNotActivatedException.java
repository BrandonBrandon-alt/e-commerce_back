// exceptions/AccountNotActivatedException.java
package com.e_commerce.e_commerce_back.exception;

public class AccountNotActivatedException extends RuntimeException {
    public AccountNotActivatedException(String message) {
        super(message);
    }
}