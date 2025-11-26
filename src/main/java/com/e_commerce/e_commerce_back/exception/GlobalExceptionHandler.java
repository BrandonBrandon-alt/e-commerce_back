package com.e_commerce.e_commerce_back.exception;

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

    // Helper method to create consistent error response
    private ResponseEntity<Map<String, Object>> createErrorResponse(
            HttpStatus status, String error, String message, String path, String code) {
        return createErrorResponse(status, error, message, path, code, null);
    }

    private ResponseEntity<Map<String, Object>> createErrorResponse(
            HttpStatus status, String error, String message, String path, String code,
            Map<String, Object> additionalData) {

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", status.value());
        response.put("error", error);
        response.put("message", message);
        response.put("path", path);
        response.put("code", code); // New field for stable error handling

        if (additionalData != null) {
            response.putAll(additionalData);
        }

        return ResponseEntity.status(status).body(response);
    }

    // ========================================================================
    // 1. EXCEPCIONES PERSONALIZADAS DE AUTENTICACIÓN (PRIORIDAD)
    // ========================================================================

    /**
     * Maneja todas las excepciones personalizadas base de autenticación
     */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Map<String, Object>> handleAuthException(AuthException ex, WebRequest request) {
        log.error("Auth exception: {} - Status: {}", ex.getMessage(), ex.getStatus());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(ex.getStatus(), ex.getStatus().getReasonPhrase(), ex.getMessage(), path,
                "AUTH_ERROR");
    }

    /**
     * Maneja credenciales incorrectas con intentos restantes
     */
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidCredentials(
            InvalidCredentialsException ex, WebRequest request) {
        log.warn("Invalid credentials: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");

        Map<String, Object> data = new HashMap<>();
        if (ex.getRemainingAttempts() > 0) {
            data.put("remainingAttempts", ex.getRemainingAttempts());
        }

        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", ex.getMessage(), path,
                "INVALID_CREDENTIALS", data);
    }

    /**
     * Maneja cuenta bloqueada con tiempo restante (NUEVA EXCEPCIÓN)
     */
    @ExceptionHandler(AccountLockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            AccountLockedException ex, WebRequest request) {
        log.warn("Account locked: {} - Remaining: {} minutes", ex.getMessage(), ex.getRemainingMinutes());
        String path = request.getDescription(false).replace("uri=", "");

        Map<String, Object> data = new HashMap<>();
        if (ex.getRemainingMinutes() > 0) {
            data.put("remainingMinutes", ex.getRemainingMinutes());
            data.put("retryAfter", ex.getRemainingMinutes() * 60); // segundos
        }

        return ResponseEntity.status(HttpStatus.LOCKED)
                .header("Retry-After", String.valueOf(ex.getRemainingMinutes() * 60))
                .body(createErrorResponse(HttpStatus.LOCKED, "Account Locked", ex.getMessage(), path, "ACCOUNT_LOCKED",
                        data).getBody());
    }

    /**
     * Maneja cuenta no activada (NUEVA EXCEPCIÓN)
     */
    @ExceptionHandler(AccountNotActivatedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountNotActivated(
            AccountNotActivatedException ex, WebRequest request) {
        log.warn("Account not activated: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.FORBIDDEN, "Forbidden", ex.getMessage(), path, "ACCOUNT_NOT_ACTIVATED");
    }

    /**
     * Maneja errores al desbloquear cuenta
     */
    @ExceptionHandler(UnlockAccountException.class)
    public ResponseEntity<Map<String, Object>> handleUnlockAccountException(
            UnlockAccountException ex, WebRequest request) {
        log.error("Error desbloqueando cuenta: {}", ex.getMessage(), ex);
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Unlock Account Error",
                "Error al desbloquear la cuenta. Intenta nuevamente.", path, "UNLOCK_ERROR");
    }

    /**
     * Maneja errores al enviar emails
     */
    @ExceptionHandler(EmailServiceException.class)
    public ResponseEntity<Map<String, Object>> handleEmailServiceException(
            EmailServiceException ex, WebRequest request) {
        log.error("Error enviando email: {}", ex.getMessage(), ex);

        String path = request.getDescription(false).replace("uri=", "");
        String message;

        if (path.contains("/forgot-password") || path.contains("/resend-reset-code")) {
            message = "No pudimos enviar el código de reseteo a tu email. Verifica que tu correo sea válido o intenta más tarde.";
        } else if (path.contains("/register") || path.contains("/resend-activation-code")) {
            message = "No pudimos enviar el código de activación a tu email. Verifica que tu correo sea válido o intenta más tarde.";
        } else if (path.contains("/request-unlock")) {
            message = "No pudimos enviar el código de desbloqueo a tu email. Verifica que tu correo sea válido o intenta más tarde.";
        } else {
            message = "Error al enviar el email. Por favor intenta nuevamente.";
        }

        return createErrorResponse(HttpStatus.SERVICE_UNAVAILABLE, "Email Service Error", message, path,
                "EMAIL_SERVICE_ERROR");
    }

    /**
     * Maneja cuenta ya activada (OPCIONAL - si no existe)
     */
    @ExceptionHandler(AccountAlreadyActiveException.class)
    public ResponseEntity<Map<String, Object>> handleAccountAlreadyActive(
            AccountAlreadyActiveException ex, WebRequest request) {
        log.info("Intento de activar cuenta ya activa: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.CONFLICT, "Account Already Active", ex.getMessage(), path,
                "ACCOUNT_ALREADY_ACTIVE");
    }

    /**
     * Maneja demasiados intentos (rate limiting)
     */
    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<Map<String, Object>> handleTooManyAttempts(
            TooManyAttemptsException ex, WebRequest request) {
        log.warn("Too many attempts: {}", ex.getMessage());

        String path = request.getDescription(false).replace("uri=", "");
        long retryAfter = ex.getRetryAfterSeconds();
        long minutes = retryAfter / 60;

        String message;
        if (path.contains("/forgot-password") || path.contains("/resend-reset-code")) {
            message = String.format(
                    "Has solicitado demasiados códigos de reseteo. Por favor espera %d minutos antes de intentar nuevamente.",
                    minutes);
        } else if (path.contains("/resend-activation-code")) {
            message = String.format(
                    "Has solicitado demasiados códigos de activación. Por favor espera %d minutos antes de intentar nuevamente.",
                    minutes);
        } else {
            message = ex.getMessage();
        }

        Map<String, Object> data = new HashMap<>();
        data.put("retryAfterSeconds", retryAfter);
        data.put("retryAfterMinutes", minutes);

        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(retryAfter))
                .body(createErrorResponse(HttpStatus.TOO_MANY_REQUESTS, "Too Many Requests", message, path,
                        "TOO_MANY_ATTEMPTS", data).getBody());
    }

    /**
     * Maneja token OAuth inválido
     */
    @ExceptionHandler(InvalidOAuthTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidOAuthToken(
            InvalidOAuthTokenException ex, WebRequest request) {
        log.error("Invalid OAuth token: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Invalid OAuth Token", ex.getMessage(), path,
                "INVALID_OAUTH_TOKEN");
    }

    /**
     * Maneja errores de servicio OAuth externo
     */
    @ExceptionHandler(ExternalOAuthServiceException.class)
    public ResponseEntity<Map<String, Object>> handleExternalOAuthService(
            ExternalOAuthServiceException ex, WebRequest request) {
        log.error("External OAuth service error: {}", ex.getMessage(), ex);
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.BAD_GATEWAY, "External Service Error", ex.getMessage(), path,
                "EXTERNAL_OAUTH_ERROR");
    }

    /**
     * Maneja email ya registrado (NUEVA - reemplaza EmailIsExists)
     */
    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex, WebRequest request) {
        log.warn("Email already exists: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.CONFLICT, "Conflict", ex.getMessage(), path, "EMAIL_ALREADY_EXISTS");
    }

    /**
     * Maneja ID number ya registrado (NUEVA - reemplaza IdNumberIsExists)
     */
    @ExceptionHandler(IdNumberAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleIdNumberAlreadyExists(
            IdNumberAlreadyExistsException ex, WebRequest request) {
        log.warn("ID number already exists: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.CONFLICT, "Conflict", ex.getMessage(), path, "ID_NUMBER_ALREADY_EXISTS");
    }

    /**
     * Maneja código de verificación inválido
     */
    @ExceptionHandler(InvalidVerificationCodeException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidVerificationCode(
            InvalidVerificationCodeException ex, WebRequest request) {
        log.warn("Invalid verification code: {}", ex.getMessage());

        String path = request.getDescription(false).replace("uri=", "");
        String message;

        if (path.contains("/reset-password")) {
            message = "El código de reseteo es incorrecto o ha expirado. Por favor solicita un nuevo código.";
        } else if (path.contains("/activate-account")) {
            message = "El código de activación es incorrecto o ha expirado. Por favor solicita un nuevo código.";
        } else if (path.contains("/verify-unlock-code")) {
            message = "El código de desbloqueo es incorrecto o ha expirado. Por favor solicita un nuevo código.";
        } else if (path.contains("/verify-email-change")) {
            message = "El código de verificación es incorrecto o ha expirado. Por favor solicita un nuevo código.";
        } else {
            message = ex.getMessage();
        }

        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", message, path, "INVALID_VERIFICATION_CODE");
    }

    /**
     * Maneja usuario no encontrado (NUEVA - reemplaza UsernameNotFoundException)
     */
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUserNotFound(
            UserNotFoundException ex, WebRequest request) {
        log.warn("User not found: {}", ex.getMessage());

        String path = request.getDescription(false).replace("uri=", "");
        String message;

        if (path.contains("/forgot-password") || path.contains("/reset-password")) {
            message = "El correo electrónico no está registrado en el sistema";
        } else {
            message = "Email o contraseña incorrectos";
        }

        return createErrorResponse(HttpStatus.NOT_FOUND, "Not Found", message, path, "USER_NOT_FOUND");
    }

    /**
     * Maneja forgot password con mensaje genérico por seguridad
     */
    @ExceptionHandler(ForgotPasswordException.class)
    public ResponseEntity<Map<String, Object>> handleForgotPassword(
            ForgotPasswordException ex, WebRequest request) {
        log.info("Forgot password request for non-existent email (security): {}",
                request.getDescription(false));
        String path = request.getDescription(false).replace("uri=", "");

        Map<String, Object> data = new HashMap<>();
        data.put("success", true);

        // Retorna 200 OK pero con estructura consistente
        return ResponseEntity
                .ok(createErrorResponse(HttpStatus.OK, null, ex.getMessage(), path, "FORGOT_PASSWORD_SUCCESS", data)
                        .getBody());
    }

    /**
     * Maneja contraseñas que no coinciden
     */
    @ExceptionHandler(PasswordMismatchException.class)
    public ResponseEntity<Map<String, Object>> handlePasswordMismatch(
            PasswordMismatchException ex, WebRequest request) {
        log.warn("Password mismatch: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), path, "PASSWORD_MISMATCH");
    }

    /**
     * Maneja contraseña débil
     */
    @ExceptionHandler(WeakPasswordException.class)
    public ResponseEntity<Map<String, Object>> handleWeakPassword(
            WeakPasswordException ex, WebRequest request) {
        log.warn("Weak password: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), path, "WEAK_PASSWORD");
    }

    /**
     * Maneja cuenta deshabilitada
     */
    @ExceptionHandler(AccountDisabledException.class)
    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            AccountDisabledException ex, WebRequest request) {
        log.warn("Account disabled: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.FORBIDDEN, "Forbidden", ex.getMessage(), path, "ACCOUNT_DISABLED");
    }

    /**
     * Maneja emails que no coinciden
     */
    @ExceptionHandler(EmailMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleEmailMismatch(
            EmailMismatchException ex, WebRequest request) {
        log.warn("Email mismatch: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), path, "EMAIL_MISMATCH");
    }

    /**
     * Maneja entrada inválida
     */
    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidInput(
            InvalidInputException ex, WebRequest request) {
        log.warn("Invalid input: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Bad Request", ex.getMessage(), path, "INVALID_INPUT");
    }

    /**
     * Maneja refresh token inválido
     */
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidRefreshToken(
            InvalidRefreshTokenException ex, WebRequest request) {
        log.warn("Invalid refresh token: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", ex.getMessage(), path,
                "INVALID_REFRESH_TOKEN");
    }

    /**
     * Maneja token inválido
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidToken(
            InvalidTokenException ex, WebRequest request) {
        log.warn("Invalid token: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", ex.getMessage(), path, "INVALID_TOKEN");
    }

    /**
     * Maneja sesión inválida
     */
    @ExceptionHandler(InvalidSessionException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidSession(
            InvalidSessionException ex, WebRequest request) {
        log.warn("Invalid session: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", ex.getMessage(), path, "INVALID_SESSION");
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

        String path = request.getDescription(false).replace("uri=", "");
        Map<String, Object> data = new HashMap<>();
        data.put("errors", errors);

        log.warn("Validation error: {}", errors);
        return createErrorResponse(HttpStatus.BAD_REQUEST, "Validation Failed",
                "Los datos proporcionados no son válidos", path, "VALIDATION_ERROR", data);
    }

    // ========================================================================
    // 4. SPRING SECURITY (LEGACY - Standardized)
    // ========================================================================

    /**
     * Maneja credenciales incorrectas de Spring Security (legacy)
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            BadCredentialsException ex, WebRequest request) {
        log.warn("Bad credentials (legacy): {}", request.getDescription(false));
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", "Email o contraseña incorrectos", path,
                "BAD_CREDENTIALS");
    }

    /**
     * Maneja usuario no encontrado de Spring Security (legacy)
     */
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUsernameNotFound(
            UsernameNotFoundException ex, WebRequest request) {
        log.warn("Username not found (legacy): {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", "Email o contraseña incorrectos", path,
                "USER_NOT_FOUND");
    }

    /**
     * Maneja cuenta deshabilitada de Spring Security (legacy)
     */
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<Map<String, Object>> handleDisabledAccount(
            DisabledException ex, WebRequest request) {
        log.warn("Cuenta deshabilitada (legacy): {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.FORBIDDEN, "Forbidden",
                "Tu cuenta está deshabilitada. Contacta al soporte.", path, "ACCOUNT_DISABLED");
    }

    /**
     * Maneja cuenta bloqueada de Spring Security (legacy)
     */
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Map<String, Object>> handleLockedAccount(
            LockedException ex, WebRequest request) {
        log.warn("Locked account (legacy): {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.LOCKED, "Locked",
                "Tu cuenta está bloqueada temporalmente. Intenta más tarde.", path, "ACCOUNT_LOCKED");
    }

    /**
     * Maneja acceso denegado
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            AccessDeniedException ex, WebRequest request) {
        log.warn("Access denied: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.FORBIDDEN, "Forbidden", "No tienes permisos para acceder a este recurso.",
                path, "ACCESS_DENIED");
    }

    // ========================================================================
    // 5. JWT ERRORS
    // ========================================================================

    /**
     * Maneja JWT expirado
     */
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<Map<String, Object>> handleExpiredJwt(ExpiredJwtException ex, WebRequest request) {
        log.warn("Expired JWT: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized",
                "Tu sesión ha expirado. Por favor inicia sesión nuevamente.", path, "TOKEN_EXPIRED");
    }

    /**
     * Maneja JWT inválido o firma incorrecta
     */
    @ExceptionHandler({ MalformedJwtException.class, SignatureException.class })
    public ResponseEntity<Map<String, Object>> handleInvalidJwt(Exception ex, WebRequest request) {
        log.warn("Invalid JWT: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized", "Token de autenticación inválido.", path,
                "TOKEN_INVALID");
    }

    // ========================================================================
    // 6. EXCEPCIONES GENÉRICAS (500)
    // ========================================================================

    /**
     * Maneja errores de autenticación genéricos
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {
        log.error("Authentication error: {}", ex.getMessage());
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "Unauthorized",
                "Error de autenticación: " + ex.getMessage(), path, "AUTHENTICATION_ERROR");
    }

    /**
     * Maneja RuntimeException genérica
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(RuntimeException ex, WebRequest request) {
        log.error("Runtime exception: ", ex);
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "Ha ocurrido un error: " + ex.getMessage(), path, "INTERNAL_ERROR");
    }

    /**
     * Maneja cualquier excepción no capturada
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGlobalException(Exception ex, WebRequest request) {
        log.error("Unhandled exception: ", ex);
        String path = request.getDescription(false).replace("uri=", "");
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error",
                "Ha ocurrido un error interno. Por favor intenta nuevamente.", path, "INTERNAL_ERROR");
    }
}