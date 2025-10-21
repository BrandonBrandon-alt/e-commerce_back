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

    // ========================================================================
    // 1. EXCEPCIONES PERSONALIZADAS DE AUTENTICACIÓN (PRIORIDAD)
    // ========================================================================

    /**
     * Maneja todas las excepciones personalizadas base de autenticación
     */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex, WebRequest request) {
        log.error("Auth exception: {} - Status: {}", ex.getMessage(), ex.getStatus());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", ex.getStatus().value());
        response.put("error", ex.getStatus().getReasonPhrase());
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(ex.getStatus()).body(response);
    }

    /**
     * Maneja credenciales incorrectas con intentos restantes
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(
            InvalidCredentialsException ex, WebRequest request) {
        log.warn("Invalid credentials: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "Unauthorized");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        // Agregar intentos restantes si están disponibles
        if (ex.getRemainingAttempts() > 0) {
            response.put("remainingAttempts", ex.getRemainingAttempts());
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja cuenta bloqueada con tiempo restante (NUEVA EXCEPCIÓN)
     */
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            AccountLockedException ex, WebRequest request) {
        log.warn("Account locked: {} - Remaining: {} minutes", ex.getMessage(), ex.getRemainingMinutes());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.LOCKED.value());
        response.put("error", "Account Locked");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        if (ex.getRemainingMinutes() > 0) {
            response.put("remainingMinutes", ex.getRemainingMinutes());
            response.put("retryAfter", ex.getRemainingMinutes() * 60); // segundos
        }

        return ResponseEntity.status(HttpStatus.LOCKED)
                .header("Retry-After", String.valueOf(ex.getRemainingMinutes() * 60))
                .body(response);
    }

    /**
     * Maneja cuenta no activada (NUEVA EXCEPCIÓN)
     */
    @ExceptionHandler(AccountNotActivatedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountNotActivated(
            AccountNotActivatedException ex, WebRequest request) {
        log.warn("Account not activated: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.FORBIDDEN.value());
        response.put("error", "Forbidden");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * Maneja errores al desbloquear cuenta
     */
    @ExceptionHandler(UnlockAccountException.class)
    public ResponseEntity<Map<String, Object>> handleUnlockAccountException(
            UnlockAccountException ex, WebRequest request) {
        log.error("Error desbloqueando cuenta: {}", ex.getMessage(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("error", "Unlock Account Error");
        response.put("message", "Error al desbloquear la cuenta. Intenta nuevamente.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Maneja errores al enviar emails (OPCIONAL - si aún no existe)
     */
    @ExceptionHandler(EmailServiceException.class)
    public ResponseEntity<Map<String, Object>> handleEmailServiceException(
            EmailServiceException ex, WebRequest request) {
        log.error("Error enviando email: {}", ex.getMessage(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.SERVICE_UNAVAILABLE.value());
        response.put("error", "Email Service Error");
        response.put("message", "Error al enviar el email. Intenta nuevamente.");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response);
    }

    /**
     * Maneja cuenta ya activada (OPCIONAL - si no existe)
     */
    @ExceptionHandler(AccountAlreadyActiveException.class)
    public ResponseEntity<Map<String, Object>> handleAccountAlreadyActive(
            AccountAlreadyActiveException ex, WebRequest request) {
        log.info("Intento de activar cuenta ya activa: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.CONFLICT.value());
        response.put("error", "Account Already Active");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    /**
     * Maneja demasiados intentos (rate limiting)
     */
    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<Map<String, Object>> handleTooManyAttempts(
            TooManyAttemptsException ex, WebRequest request) {
        log.warn("Too many attempts: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
        response.put("error", "Too Many Requests");
        response.put("message", ex.getMessage());
        response.put("retryAfterSeconds", ex.getRetryAfterSeconds());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(ex.getRetryAfterSeconds()))
                .body(response);
    }

    /**
     * Maneja token OAuth inválido
     */
    @ExceptionHandler(InvalidOAuthTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidOAuthToken(
            InvalidOAuthTokenException ex, WebRequest request) {
        log.error("Invalid OAuth token: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "Invalid OAuth Token");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja errores de servicio OAuth externo
     */
    @ExceptionHandler(ExternalOAuthServiceException.class)
    public ResponseEntity<Map<String, Object>> handleExternalOAuthService(
            ExternalOAuthServiceException ex, WebRequest request) {
        log.error("External OAuth service error: {}", ex.getMessage(), ex);

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.BAD_GATEWAY.value());
        response.put("error", "External Service Error");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(response);
    }

    /**
     * Maneja email ya registrado (NUEVA - reemplaza EmailIsExists)
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex, WebRequest request) {
        log.warn("Email already exists: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.CONFLICT.value());
        response.put("error", "Conflict");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    /**
     * Maneja ID number ya registrado (NUEVA - reemplaza IdNumberIsExists)
     */
    @ExceptionHandler(IdNumberAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleIdNumberAlreadyExists(
            IdNumberAlreadyExistsException ex, WebRequest request) {
        log.warn("ID number already exists: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.CONFLICT.value());
        response.put("error", "Conflict");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    /**
     * Maneja código de verificación inválido
     */
    @ExceptionHandler(InvalidVerificationCodeException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidVerificationCode(
            InvalidVerificationCodeException ex, WebRequest request) {
        log.warn("Invalid verification code: {}", ex.getMessage());

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "Unauthorized");
        response.put("message", ex.getMessage());
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Maneja usuario no encontrado (NUEVA - reemplaza UsernameNotFoundException)
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUserNotFound(
            UserNotFoundException ex, WebRequest request) {
        log.warn("User not found: {}", ex.getMessage());

        // Por seguridad, no revelar si el usuario existe o no
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "Unauthorized");
        response.put("message", "Incorrect email or password");
        response.put("path", request.getDescription(false).replace("uri=", ""));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    // ========================================================================
    // 3. VALIDACIÓN DE CAMPOS (400)
    // ========================================================================

    /**
     * Maneja errores de validación de campos (@Valid)
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {

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

    // ========================================================================
    // 4. SPRING SECURITY (LEGACY - mantener para compatibilidad)
    // ========================================================================

    /**
     * Maneja credenciales incorrectas de Spring Security (legacy)
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<AuthResponseDTO> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {
        log.warn("Bad credentials (legacy): {}", request.getDescription(false));
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error(ex.getMessage()));
    }

    /**
     * Maneja usuario no encontrado de Spring Security (legacy)
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<AuthResponseDTO> handleUsernameNotFound(
            UsernameNotFoundException ex, WebRequest request) {
        log.warn("Username not found (legacy): {}", ex.getMessage());
        // Por seguridad, no revelar que el usuario no existe
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Email o contraseña incorrectos"));
    }

    /**
     * Maneja cuenta deshabilitada de Spring Security (legacy)
     */
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<AuthResponseDTO> handleDisabledAccount(
            DisabledException ex, WebRequest request) {
        log.warn("Cuenta deshabilitada (legacy): {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(AuthResponseDTO.error("Tu cuenta está deshabilitada. Contacta al soporte."));
    }

    /**
     * Maneja cuenta bloqueada de Spring Security (legacy)
     */
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<AuthResponseDTO> handleLockedAccount(
            LockedException ex, WebRequest request) {
        log.warn("Locked account (legacy): {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.LOCKED)
                .body(AuthResponseDTO.error("Tu cuenta está bloqueada temporalmente. Intenta más tarde."));
    }

    /**
     * Maneja acceso denegado
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthResponseDTO> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {
        log.warn("Access denied: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(AuthResponseDTO.error("No tienes permisos para acceder a este recurso."));
    }

    // ========================================================================
    // 5. JWT ERRORS
    // ========================================================================

    /**
     * Maneja JWT expirado
     */
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<AuthResponseDTO> handleExpiredJwt(ExpiredJwtException ex) {
        log.warn("Expired JWT: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Tu sesión ha expirado. Por favor inicia sesión nuevamente."));
    }

    /**
     * Maneja JWT inválido o firma incorrecta
     */
    @ExceptionHandler({ MalformedJwtException.class, SignatureException.class })
    public ResponseEntity<AuthResponseDTO> handleInvalidJwt(Exception ex) {
        log.warn("Invalid JWT: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Token de autenticación inválido."));
    }

    // ========================================================================
    // 6. EXCEPCIONES GENÉRICAS (500)
    // ========================================================================

    /**
     * Maneja errores de autenticación genéricos
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<AuthResponseDTO> handleAuthenticationException(
            AuthenticationException ex) {
        log.error("Authentication error: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(AuthResponseDTO.error("Error de autenticación: " + ex.getMessage()));
    }

    /**
     * Maneja RuntimeException genérica
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<AuthResponseDTO> handleRuntimeException(RuntimeException ex) {
        log.error("Runtime exception: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthResponseDTO.error("Ha ocurrido un error: " + ex.getMessage()));
    }

    /**
     * Maneja cualquier excepción no capturada
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthResponseDTO> handleGlobalException(Exception ex) {
        log.error("Unhandled exception: ", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(AuthResponseDTO.error("Ha ocurrido un error interno. Por favor intenta nuevamente."));
    }
}

// ============================================================================
// RESUMEN DE CAMBIOS
// ============================================================================
/*
 * ✅ NUEVAS EXCEPCIONES AGREGADAS:
 * - InvalidCredentialsException (con intentos restantes)
 * - AccountLockedException (con tiempo restante)
 * - TooManyAttemptsException (rate limiting)
 * - InvalidOAuthTokenException
 * - ExternalOAuthServiceException
 * - EmailAlreadyExistsException
 * - IdNumberAlreadyExistsException
 * - InvalidVerificationCodeException
 * - UserNotFoundException
 * 
 * ✅ EXCEPCIONES LEGACY MANTENIDAS:
 * - EmailIsExists (deprecated)
 * - IdNumberIsExists (deprecated)
 * - BadCredentialsException (Spring Security)
 * - UsernameNotFoundException (Spring Security)
 * - DisabledException, LockedException, etc.
 * 
 * ✅ BENEFICIOS:
 * 1. Respuestas más consistentes y detalladas
 * 2. Metadata adicional (remainingAttempts, retryAfter, etc.)
 * 3. Headers HTTP apropiados (Retry-After)
 * 4. Mejor logging y debugging
 * 5. Compatibilidad con código existente
 * 6. Migraci gradual de excepciones legacy a nuevas
 */