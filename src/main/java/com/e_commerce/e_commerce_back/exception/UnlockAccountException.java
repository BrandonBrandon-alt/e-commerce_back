package com.e_commerce.e_commerce_back.exception;

/**
 * Excepción lanzada cuando hay un error al desbloquear una cuenta
 */
public class UnlockAccountException extends RuntimeException {
    
    /**
     * Constructor con mensaje
     * 
     * @param message Mensaje descriptivo del error
     */
    public UnlockAccountException(String message) {
        super(message);
    }
    
    /**
     * Constructor con mensaje y causa
     * 
     * @param message Mensaje descriptivo del error
     * @param cause Excepción que causó este error
     */
    public UnlockAccountException(String message, Throwable cause) {
        super(message, cause);
    }
}
