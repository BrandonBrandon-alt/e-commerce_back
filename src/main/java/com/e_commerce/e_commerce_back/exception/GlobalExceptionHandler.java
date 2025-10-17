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

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /* 🧩 Validación de campos */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex,
            WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            errors.put(fieldName, error.getDefaultMessage());
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

    /* ⚙️ Errores de autenticación */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<AuthResponseDTO> handleBadCredentials(BadCredentialsException ex, WebRequest request) {
        log.warn("Bad credentials: {}", request.getDescription(false));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Email o contraseña incorrectos"));
    }

    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<AuthResponseDTO> handleAccountLocked(AccountLockedException ex, WebRequest request) {
        log.warn("Cuenta bloqueada: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(AuthResponseDTO.error(ex.getMessage()));
    }

    @ExceptionHandler(AccountNotActivatedException.class)
    public ResponseEntity<AuthResponseDTO> handleAccountNotActivated(AccountNotActivatedException ex,
            WebRequest request) {
        log.warn("Cuenta no activada: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(AuthResponseDTO.error(ex.getMessage()));
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<AuthResponseDTO> handleUsernameNotFound(UsernameNotFoundException ex, WebRequest request) {
        log.warn("Usuario no encontrado: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Email o contraseña incorrectos"));
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<AuthResponseDTO> handleDisabledAccount(DisabledException ex, WebRequest request) {
        log.warn("Cuenta deshabilitada: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(AuthResponseDTO.error("Tu cuenta está deshabilitada. Contacta al soporte."));
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<AuthResponseDTO> handleLockedAccount(LockedException ex, WebRequest request) {
        log.warn("Locked account: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(AuthResponseDTO.error("Tu cuenta está bloqueada temporalmente. Intenta más tarde."));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthResponseDTO> handleAccessDenied(AccessDeniedException ex, WebRequest request) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(AuthResponseDTO.error("No tienes permisos para acceder a este recurso."));
    }

    /* 🔐 JWT */
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<AuthResponseDTO> handleExpiredJwt(ExpiredJwtException ex) {
        log.warn("Expired JWT: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Tu sesión ha expirado. Por favor inicia sesión nuevamente."));
    }

    @ExceptionHandler({ MalformedJwtException.class, SignatureException.class })
    public ResponseEntity<AuthResponseDTO> handleInvalidJwt(Exception ex) {
        log.warn("Invalid JWT: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Token de autenticación inválido."));
    }

    /* ⚠️ Otros errores */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<AuthResponseDTO> handleAuthenticationException(AuthenticationException ex) {
        log.error("Authentication error: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Error de autenticación: " + ex.getMessage()));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<AuthResponseDTO> handleRuntimeException(RuntimeException ex) {
        log.error("Runtime exception: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthResponseDTO.error("Ha ocurrido un error: " + ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthResponseDTO> handleGlobalException(Exception ex) {
        log.error("Unhandled exception: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthResponseDTO.error("Ha ocurrido un error interno. Por favor intenta nuevamente."));
    }
}
