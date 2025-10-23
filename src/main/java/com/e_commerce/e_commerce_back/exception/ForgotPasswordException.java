package com.e_commerce.e_commerce_back.exception;

import org.springframework.http.HttpStatus;

/**
 * Excepción para forgot password que retorna mensaje genérico por seguridad
 * Evita revelar si un email está registrado o no
 */
public class ForgotPasswordException extends AuthException {
    public ForgotPasswordException(String message) {
        super(message, HttpStatus.OK); // 200 para no revelar si el email existe
    }
}
