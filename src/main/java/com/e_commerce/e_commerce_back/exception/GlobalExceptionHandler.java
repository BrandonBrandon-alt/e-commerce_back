package com.e_commerce.e_commerce_back.exception;

import com.e_commerce.e_commerce_back.dto.AuthResponseDTO;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Manejador global de excepciones para la aplicación
 * Captura y procesa todas las excepciones de seguridad y validación
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Maneja excepciones de validación de campos
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Validation Failed");
        response.put("message", "Los datos proporcionados no son válidos");
        response.put("errors", errors);
        response.put("path", request.getDescription(false).replace("uri=", ""));

        log.warn("Validation error: {}", errors);
        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Maneja excepciones de autenticación (credenciales inválidas)
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<AuthResponseDTO> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {
        
        log.warn("Bad credentials attempt from: {}", request.getDescription(false));
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "Credenciales inválidas. Por favor verifica tu email y contraseña."
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja excepciones cuando el usuario no existe
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<AuthResponseDTO> handleUsernameNotFound(
            UsernameNotFoundException ex, WebRequest request) {
        
        log.warn("User not found: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error("Usuario no encontrado");

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
    }

    /**
     * Maneja excepciones cuando la cuenta está deshabilitada
     */
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<AuthResponseDTO> handleDisabledAccount(
            DisabledException ex, WebRequest request) {
        
        log.warn("Disabled account login attempt: {}", request.getDescription(false));
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "Tu cuenta está deshabilitada. Por favor contacta al soporte."
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * Maneja excepciones cuando la cuenta está bloqueada
     */
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<AuthResponseDTO> handleLockedAccount(
            LockedException ex, WebRequest request) {
        
        log.warn("Locked account login attempt: {}", request.getDescription(false));
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "Tu cuenta está bloqueada temporalmente. Por favor intenta más tarde o solicita un desbloqueo."
        );

        return ResponseEntity.status(HttpStatus.LOCKED).body(response);
    }

    /**
     * Maneja excepciones de acceso denegado
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthResponseDTO> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {
        
        log.warn("Access denied: {} - {}", request.getDescription(false), ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "No tienes permisos para acceder a este recurso"
        );

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * Maneja excepciones de JWT expirado
     */
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<AuthResponseDTO> handleExpiredJwt(
            ExpiredJwtException ex, WebRequest request) {
        
        log.warn("Expired JWT token: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "Tu sesión ha expirado. Por favor inicia sesión nuevamente."
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja excepciones de JWT malformado
     */
    @ExceptionHandler(MalformedJwtException.class)
    public ResponseEntity<AuthResponseDTO> handleMalformedJwt(
            MalformedJwtException ex, WebRequest request) {
        
        log.warn("Malformed JWT token: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error("Token de autenticación inválido");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja excepciones de firma JWT inválida
     */
    @ExceptionHandler(SignatureException.class)
    public ResponseEntity<AuthResponseDTO> handleInvalidJwtSignature(
            SignatureException ex, WebRequest request) {
        
        log.error("Invalid JWT signature: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error("Token de autenticación inválido");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja excepciones generales de autenticación
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<AuthResponseDTO> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {
        
        log.error("Authentication error: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "Error de autenticación: " + ex.getMessage()
        );

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja excepciones de cuenta bloqueada personalizada
     */
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<AuthResponseDTO> handleAccountLocked(
            AccountLockedException ex, WebRequest request) {
        
        log.warn("Account locked: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error(ex.getMessage());

        return ResponseEntity.status(HttpStatus.LOCKED).body(response);
    }

    /**
     * Maneja excepciones genéricas no capturadas
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGlobalException(
            Exception ex, WebRequest request) {
        
        log.error("Unhandled exception: {}", ex.getMessage(), ex);
        
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("error", "Internal Server Error");
        response.put("message", "Ha ocurrido un error interno. Por favor intenta nuevamente.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Maneja excepciones de runtime genéricas
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<AuthResponseDTO> handleRuntimeException(
            RuntimeException ex, WebRequest request) {
        
        log.error("Runtime exception: {}", ex.getMessage(), ex);
        
        AuthResponseDTO response = AuthResponseDTO.error(
                "Ha ocurrido un error: " + ex.getMessage()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Maneja excepciones de argumento ilegal
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<AuthResponseDTO> handleIllegalArgument(
            IllegalArgumentException ex, WebRequest request) {
        
        log.warn("Illegal argument: {}", ex.getMessage());
        
        AuthResponseDTO response = AuthResponseDTO.error(ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
