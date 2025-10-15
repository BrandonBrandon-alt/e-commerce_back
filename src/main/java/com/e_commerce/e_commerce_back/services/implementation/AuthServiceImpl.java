package com.e_commerce.e_commerce_back.services.implementation;

import com.e_commerce.e_commerce_back.dto.*;
import com.e_commerce.e_commerce_back.entity.User;
import com.e_commerce.e_commerce_back.exception.EmailIsExists;
import com.e_commerce.e_commerce_back.exception.IdNumberIsExists;
import com.e_commerce.e_commerce_back.repository.UserRepository;
import com.e_commerce.e_commerce_back.security.JwtUtil;
import com.e_commerce.e_commerce_back.services.interfaces.AuthService;
import com.e_commerce.e_commerce_back.services.interfaces.EmailService;
import com.e_commerce.enums.EnumRole;
import com.e_commerce.enums.EnumStatus;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * Implementación del servicio de autenticación
 * Maneja login, registro y operaciones JWT con seguridad mejorada
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;
    private final TokenRedisService tokenRedisService;
    private final JwtSessionService jwtSessionService;
    private final AccountLockoutRedisService accountLockoutRedisService;
    private final GoogleOAuthService googleOAuthService;

    @Value("${app.jwt.expiration}")
    private Long jwtExpiration;

    @Value("${app.security.max-failed-attempts:5}")
    private Integer maxFailedAttempts;

    @Value("${app.security.lockout-duration-minutes:15}")
    private Integer lockoutDurationMinutes;

    // ============================================================================
    // REGISTRO Y ACTIVACIÓN
    // ============================================================================

    @Override
    public AuthResponseDTO register(RegisterUserDTO createUserDTO) {
        String normalizedEmail = createUserDTO.email().toLowerCase().trim();
        log.info("Procesando registro para email: {}", normalizedEmail);

        try {
            if (userRepository.existsByEmail(normalizedEmail)) {
                throw new EmailIsExists("El email ya está registrado");
            }

            if (userRepository.findByIdNumber(createUserDTO.idNumber()).isPresent()) {
                throw new IdNumberIsExists("El número de identificación ya está registrado");
            }

            User newUser = User.builder()
                    .idNumber(createUserDTO.idNumber())
                    .name(createUserDTO.name())
                    .lastName(createUserDTO.lastName())
                    .email(normalizedEmail)
                    .phoneNumber(createUserDTO.phoneNumber())
                    .password(passwordEncoder.encode(createUserDTO.password()))
                    .dateOfBirth(createUserDTO.dateOfBirth())
                    .role(EnumRole.USER)
                    .status(EnumStatus.INACTIVE)
                    .emailVerified(false)
                    .phoneVerified(false)
                    .build();

            User savedUser = userRepository.save(newUser);
            String activationCode = tokenRedisService.generateAndStoreActivationCode(savedUser.getId());

            log.info("Usuario registrado exitosamente: {} - ID: {}",
                    savedUser.getEmail(), savedUser.getId());

            try {
                emailService.sendActivationEmail(savedUser, activationCode);
                log.info("Email de activación enviado a: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Error enviando email de activación a {}: {}",
                        savedUser.getEmail(), e.getMessage());
            }

            return AuthResponseDTO.registered(
                    "Usuario registrado exitosamente. Revisa tu email para activar tu cuenta con el código de 6 dígitos.");

        } catch (EmailIsExists | IdNumberIsExists e) {
            log.warn("Error de registro - {}: {}", e.getClass().getSimpleName(), e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Error en registro para email: {}, error: {}", normalizedEmail, e.getMessage());
            throw new RuntimeException("Error interno del servidor durante el registro");
        }
    }

    @Override
    @Transactional
    public AuthResponseDTO activateAccount(ActivateAccountDTO activateAccountDTO) {
        log.info("Procesando activación de cuenta con código: {}", activateAccountDTO.activationCode());

        try {
            Long userId = tokenRedisService.verifyAndConsumeActivationCode(activateAccountDTO.activationCode());

            if (userId == null) {
                log.warn("Código de activación inválido o expirado");
                return AuthResponseDTO.error("Código de activación incorrecto o expirado");
            }

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con ID: " + userId));

            if (user.getStatus() == EnumStatus.ACTIVE && Boolean.TRUE.equals(user.getEmailVerified())) {
                log.info("La cuenta del usuario {} ya está activada", user.getEmail());
                return AuthResponseDTO.error("La cuenta ya está activada");
            }

            log.info("Estado antes de activar - Status: {}, EmailVerified: {}",
                    user.getStatus(), user.getEmailVerified());

            user.setStatus(EnumStatus.ACTIVE);
            user.setEmailVerified(true);

            User savedUser = userRepository.save(user);
            userRepository.flush();

            log.info("Estado después de activar - Status: {}, EmailVerified: {}, isEnabled: {}",
                    savedUser.getStatus(), savedUser.getEmailVerified(), savedUser.isEnabled());

            log.info("Cuenta activada exitosamente para usuario ID: {} - Email: {}",
                    userId, savedUser.getEmail());

            try {
                emailService.sendWelcomeEmail(savedUser);
                log.info("Email de bienvenida enviado a: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Error enviando email de bienvenida a {}: {}", savedUser.getEmail(), e.getMessage());
            }

            return AuthResponseDTO.success("¡Cuenta activada exitosamente! Ya puedes iniciar sesión.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al activar cuenta: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error en activación de cuenta: ", e);
            return AuthResponseDTO.error("Error al activar la cuenta: " + e.getMessage());
        }
    }

    @Override
    public AuthResponseDTO resendActivationCode(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        log.info("Procesando reenvío de código de activación para email: {}", normalizedEmail);

        try {
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            if (user.isEnabled()) {
                return AuthResponseDTO.error("La cuenta ya está activada");
            }

            if (!tokenRedisService.canRequestToken(user.getId(), "activation")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            String newActivationCode = tokenRedisService.generateAndStoreActivationCode(user.getId());
            log.info("Nuevo código de activación generado para usuario: {}", email);

            try {
                emailService.sendActivationEmail(user, newActivationCode);
                log.info("Nuevo email de activación enviado a: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Error enviando nuevo email de activación a {}: {}",
                        user.getEmail(), e.getMessage());
                return AuthResponseDTO.error("Error enviando el email de activación");
            }

            return AuthResponseDTO.success("Nuevo código de activación enviado. Revisa tu email.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de reenvío con email no registrado: {}", normalizedEmail);
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error en reenvío para email: {}, error: {}", normalizedEmail, e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    // ============================================================================
    // LOGIN Y LOGOUT
    // ============================================================================

    @Override
    public AuthResponseDTO login(LoginDTO loginDTO) {
        String normalizedEmail = loginDTO.email().toLowerCase().trim();
        log.info("Procesando login para email: {}", normalizedEmail);

        try {
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Verificar bloqueo en Redis (prioridad sobre BD)
            if (accountLockoutRedisService.isAccountLocked(user.getId())) {
                Duration remainingTime = accountLockoutRedisService.getRemainingLockoutTime(user.getId());
                log.warn("Intento de login en cuenta bloqueada (Redis): {} - Tiempo restante: {} minutos",
                        normalizedEmail, remainingTime.toMinutes());
                throw new BadCredentialsException(
                        String.format("Cuenta temporalmente bloqueada. Intenta nuevamente en %d minutos",
                                remainingTime.toMinutes()));
            }

            if (!user.isEnabled()) {
                throw new BadCredentialsException("Cuenta no activada. Verifica tu email.");
            }

            // Validar contraseña manualmente para tener control total del flujo
            if (!passwordEncoder.matches(loginDTO.password(), user.getPassword())) {
                log.warn("Contraseña incorrecta para usuario: {}", normalizedEmail);
                // handleFailedLogin lanza BadCredentialsException con el mensaje apropiado
                handleFailedLogin(user, normalizedEmail);
                // Esta línea nunca se alcanza, pero Java requiere un return
                throw new RuntimeException("Unreachable code");
            }

            // Autenticación exitosa
            handleSuccessfulLogin(user);
            JwtSessionService.SessionTokens sessionTokens = createUserSession(user);
            logLoginSuccess(user, sessionTokens);

            UserInfoDTO userInfo = UserInfoDTO.fromUser(user);

            return AuthResponseDTO.success(
                    sessionTokens.getAccessToken(),
                    sessionTokens.getRefreshToken(),
                    sessionTokens.getExpiresIn() * 1000,
                    userInfo);
        } catch (UsernameNotFoundException e) {
            log.warn("Intento de login con email no registrado: {}", normalizedEmail);
            throw new BadCredentialsException("Email o contraseña incorrectos");
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error en login para email: {}, error: {}", normalizedEmail, e.getMessage());
            throw new RuntimeException("Error interno del servidor");
        }
    }

    @Override
    public void logout(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (StringUtils.hasText(token)) {
                try {
                    String sessionId = jwtSessionService.findSessionIdByAccessToken(token);

                    if (sessionId != null) {
                        jwtSessionService.closeSession(sessionId);
                        log.info("Sesión cerrada - SessionId: {}", sessionId);
                    } else {
                        jwtSessionService.blacklistAccessToken(token);
                        log.info("Token blacklisted - Sesión no encontrada");
                    }

                } catch (Exception tokenException) {
                    log.warn("Intento de logout con token inválido: {}", tokenException.getMessage());
                    jwtSessionService.blacklistAccessToken(token);
                }

                SecurityContextHolder.clearContext();
            } else {
                log.info("Logout procesado sin token válido");
            }

        } catch (Exception e) {
            log.error("Error en logout: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }
    }

    @Override
    public AuthResponseDTO loginWithGoogle(GoogleOAuthLoginDTO googleOAuthLoginDTO) {
        log.info("Procesando login con Google OAuth");

        try {
            // Verificar el token de Google
            com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload payload = 
                googleOAuthService.verifyGoogleToken(googleOAuthLoginDTO.idToken());

            String email = googleOAuthService.getEmail(payload);
            String normalizedEmail = email.toLowerCase().trim();
            Boolean emailVerified = googleOAuthService.isEmailVerified(payload);

            log.info("Token de Google verificado para email: {}", normalizedEmail);

            // Buscar o crear usuario
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseGet(() -> {
                        log.info("Usuario no existe, creando nuevo usuario desde Google: {}", normalizedEmail);
                        
                        String givenName = googleOAuthService.getGivenName(payload);
                        String familyName = googleOAuthService.getFamilyName(payload);
                        
                        User newUser = User.builder()
                                .email(normalizedEmail)
                                .name(givenName != null ? givenName : "Google")
                                .lastName(familyName != null ? familyName : "User")
                                .idNumber("GOOGLE-" + payload.getSubject()) // ID único de Google
                                .password(passwordEncoder.encode(java.util.UUID.randomUUID().toString())) // Password aleatorio
                                .role(EnumRole.USER)
                                .status(EnumStatus.ACTIVE) // Activado automáticamente
                                .emailVerified(emailVerified != null ? emailVerified : true) // Email verificado por Google
                                .phoneVerified(false)
                                .build();

                        return userRepository.save(newUser);
                    });

            // Verificar si la cuenta está habilitada
            if (!user.isEnabled()) {
                // Si el usuario existe pero no está activado, activarlo automáticamente
                // ya que Google verificó el email
                user.setStatus(EnumStatus.ACTIVE);
                user.setEmailVerified(true);
                user = userRepository.save(user);
                log.info("Cuenta activada automáticamente por Google OAuth: {}", normalizedEmail);
            }

            // Verificar bloqueo
            if (accountLockoutRedisService.isAccountLocked(user.getId())) {
                Duration remainingTime = accountLockoutRedisService.getRemainingLockoutTime(user.getId());
                log.warn("Intento de login OAuth en cuenta bloqueada: {} - Tiempo restante: {} minutos",
                        normalizedEmail, remainingTime.toMinutes());
                throw new BadCredentialsException(
                        String.format("Cuenta temporalmente bloqueada. Intenta nuevamente en %d minutos",
                                remainingTime.toMinutes()));
            }

            // Autenticación exitosa
            handleSuccessfulLogin(user);
            JwtSessionService.SessionTokens sessionTokens = createUserSession(user);
            logLoginSuccess(user, sessionTokens);

            UserInfoDTO userInfo = UserInfoDTO.fromUser(user);

            return AuthResponseDTO.success(
                    sessionTokens.getAccessToken(),
                    sessionTokens.getRefreshToken(),
                    sessionTokens.getExpiresIn() * 1000,
                    userInfo);

        } catch (IllegalArgumentException e) {
            log.error("Token de Google inválido: {}", e.getMessage());
            throw new BadCredentialsException("Token de Google inválido");
        } catch (BadCredentialsException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error en login con Google: {}", e.getMessage(), e);
            throw new RuntimeException("Error interno del servidor");
        }
    }

    // ============================================================================
    // MANEJO DE INTENTOS FALLIDOS
    // ============================================================================

    /**
     * Maneja un intento de login fallido
     * Usa Redis para el tracking de intentos y lanza la excepción apropiada
     * 
     * @param user Usuario que intentó hacer login
     * @param email Email usado en el intento
     * @throws BadCredentialsException con mensaje apropiado según el estado de bloqueo
     */
    private void handleFailedLogin(User user, String email) {
        log.warn("Intento fallido de login para usuario: {}", email);

        // Registrar intento fallido en Redis (esto puede bloquear la cuenta automáticamente)
        int failedAttempts = accountLockoutRedisService.recordFailedAttempt(user.getId());

        // Verificar si la cuenta se bloqueó después de registrar el intento
        if (accountLockoutRedisService.isAccountLocked(user.getId())) {
            Duration remainingTime = accountLockoutRedisService.getRemainingLockoutTime(user.getId());
            log.error("Cuenta bloqueada en Redis para usuario: {} - Intentos: {} - Tiempo restante: {} minutos",
                    email, failedAttempts, remainingTime.toMinutes());
            
            throw new BadCredentialsException(
                    String.format("Cuenta bloqueada por %d minutos debido a múltiples intentos fallidos",
                            remainingTime.toMinutes()));
        }

        // Si no está bloqueada, informar intentos restantes
        int remainingAttempts = accountLockoutRedisService.getRemainingAttempts(user.getId());
        log.warn("Credenciales inválidas - Intentos fallidos: {} - Restantes: {}",
                failedAttempts, remainingAttempts);
        
        throw new BadCredentialsException(
                String.format("Email o contraseña incorrectos. Intentos restantes: %d",
                        remainingAttempts));
    }

    /**
     * Maneja un login exitoso
     * Resetea intentos fallidos en Redis y actualiza info de login
     */
    private void handleSuccessfulLogin(User user) {
        log.info("Login exitoso para usuario: {}", user.getEmail());

        // Resetear intentos fallidos en Redis
        accountLockoutRedisService.resetFailedAttempts(user.getId());

        updateLastLoginInfo(user);
        userRepository.save(user);
    }

    /**
     * @deprecated Usar accountLockoutRedisService.recordFailedAttempt() en su lugar
     *             Mantenido para compatibilidad temporal
     */
    @Deprecated
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void incrementFailedAttemptsInNewTransaction(Long userId, String email) {
        log.warn("DEPRECADO: incrementFailedAttemptsInNewTransaction - usar AccountLockoutRedisService");
        // Delegar a Redis
        accountLockoutRedisService.recordFailedAttempt(userId);
    }

    /**
     * @deprecated Usar accountLockoutRedisService.resetFailedAttempts() en su lugar
     *             Mantenido para compatibilidad temporal
     */
    @Deprecated
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void resetFailedAttemptsInNewTransaction(Long userId) {
        log.warn("DEPRECADO: resetFailedAttemptsInNewTransaction - usar AccountLockoutRedisService");
        // Delegar a Redis
        accountLockoutRedisService.resetFailedAttempts(userId);
    }

    // ============================================================================
    // DESBLOQUEO DE CUENTA
    // ============================================================================

    @Override
    public AuthResponseDTO requestImmediateUnlock(RequestImmediateUnlockDTO requestImmediateUnlockDTO) {
        String normalizedEmail = requestImmediateUnlockDTO.email().toLowerCase().trim();
        try {
            User user = userRepository.findByEmail(normalizedEmail).orElse(null);

            if (user == null) {
                return AuthResponseDTO.success("Si el correo es válido y está bloqueado, recibirás un código");
            }

            // Verificar si está bloqueado en Redis
            if (!accountLockoutRedisService.isAccountLocked(user.getId())) {
                return AuthResponseDTO.success("Si el correo es válido y está bloqueado, recibirás un código");
            }

            if (!tokenRedisService.canRequestToken(user.getId(), "unlock")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            String unlockCode = tokenRedisService.generateAndStoreUnlockCode(user.getId());
            emailService.sendUnlockCode(user, unlockCode);

            log.info("Unlock code sent to user: {}", user.getEmail());
            return AuthResponseDTO.success("Código de desbloqueo enviado a tu email");

        } catch (Exception e) {
            log.error("Error al solicitar desbloqueo inmediato: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error al enviar el código");
        }
    }

    @Override
    @Transactional
    public AuthResponseDTO verifyUnlockCode(VerifyUnlockCodeDTO verifyUnlockCodeDTO) {
        log.info("Procesando verificación de código de desbloqueo");

        try {
            Long userId = tokenRedisService.verifyAndConsumeUnlockCode(verifyUnlockCodeDTO.code());

            if (userId == null) {
                log.warn("Código de desbloqueo inválido o expirado");
                return AuthResponseDTO.error("Código de desbloqueo incorrecto o expirado");
            }

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con ID: " + userId));

            // Verificar bloqueo en Redis
            if (!accountLockoutRedisService.isAccountLocked(userId)) {
                log.info("La cuenta del usuario {} no está bloqueada en Redis", user.getEmail());
                return AuthResponseDTO.success("La cuenta ya está desbloqueada");
            }

            // Desbloquear en Redis
            accountLockoutRedisService.unlockAccount(userId);

            log.info("Cuenta desbloqueada exitosamente para usuario: {} - Email: {}", userId, user.getEmail());

            try {
                emailService.sendAccountUnlockedEmail(user);
            } catch (Exception e) {
                log.warn("Error enviando email de confirmación de desbloqueo: {}", e.getMessage());
            }

            return AuthResponseDTO.success("Cuenta desbloqueada exitosamente. Ya puedes iniciar sesión.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error al verificar código de desbloqueo: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error al verificar el código");
        }
    }

    @Transactional
    public void unlockUserAccount(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        // Desbloquear en Redis
        accountLockoutRedisService.unlockAccount(user.getId());

        log.info("Cuenta desbloqueada manualmente para usuario: {} (Redis)", normalizedEmail);
    }

    // ============================================================================
    // RECUPERACIÓN DE CONTRASEÑA
    // ============================================================================

    @Override
    public AuthResponseDTO forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {
        String normalizedEmail = forgotPasswordDTO.email().toLowerCase().trim();
        try {
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException(
                            "Usuario no encontrado con el email: " + normalizedEmail));

            if (!tokenRedisService.canRequestToken(user.getId(), "reset")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            String resetCode = tokenRedisService.generateAndStoreResetCode(user.getId());
            emailService.sendPasswordResetEmail(user, resetCode);

            log.info("Código de reseteo de contraseña enviado a: {}", normalizedEmail);
            return AuthResponseDTO.success("Se ha enviado un código de reseteo a tu correo electrónico.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de reseteo de contraseña para email no registrado: {}", normalizedEmail);
            return AuthResponseDTO.success("Si tu correo está registrado, recibirás un código de reseteo.");
        } catch (Exception e) {
            log.error("Error al procesar la solicitud de olvido de contraseña para {}: {}", normalizedEmail,
                    e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor al intentar resetear la contraseña.");
        }
    }

    @Override
    @Transactional
    public AuthResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO) {
        log.info("Procesando reseteo de contraseña");

        try {
            Long userId = tokenRedisService.verifyAndConsumeResetCode(resetPasswordDTO.resetCode());

            if (userId == null) {
                log.warn("Código de reset inválido o expirado");
                return AuthResponseDTO.error("Código de reset incorrecto o expirado");
            }

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con ID: " + userId));

            if (!resetPasswordDTO.passwordsMatch()) {
                return AuthResponseDTO.error("Las contraseñas no coinciden");
            }

            if (resetPasswordDTO.password().length() < 8) {
                return AuthResponseDTO.error("La contraseña debe tener al menos 8 caracteres");
            }

            user.setPassword(passwordEncoder.encode(resetPasswordDTO.password()));
            user.setPasswordChangedAt(LocalDateTime.now());

            userRepository.save(user);

            log.info("Contraseña restablecida exitosamente para usuario ID: {} - Email: {}",
                    userId, user.getEmail());

            try {
                emailService.sendPasswordChangedConfirmationEmail(user);
            } catch (Exception e) {
                log.warn("Error enviando email de confirmación de cambio de contraseña: {}", e.getMessage());
            }

            return AuthResponseDTO.success("Contraseña restablecida exitosamente. Ya puedes iniciar sesión.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al resetear contraseña: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error al restablecer contraseña: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    // ============================================================================
    // GESTIÓN DE CONTRASEÑA Y EMAIL
    // ============================================================================

    @Override
    @Transactional
    public AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO) {
        log.info("Procesando cambio de contraseña");

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return AuthResponseDTO.error("Usuario no autenticado");
            }

            String username = authentication.getName();
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            if (!changePasswordDTO.isPasswordConfirmationValid()) {
                return AuthResponseDTO.error("Las contraseñas no coinciden");
            }

            if (!passwordEncoder.matches(changePasswordDTO.currentPassword(), user.getPassword())) {
                log.warn("Intento de cambio de contraseña con contraseña actual incorrecta para: {}", username);
                return AuthResponseDTO.error("Contraseña actual incorrecta");
            }

            if (passwordEncoder.matches(changePasswordDTO.newPassword(), user.getPassword())) {
                return AuthResponseDTO.error("La nueva contraseña debe ser diferente a la actual");
            }

            if (changePasswordDTO.newPassword().length() < 8) {
                return AuthResponseDTO.error("La nueva contraseña debe tener al menos 8 caracteres");
            }

            if (!user.isEnabled()) {
                return AuthResponseDTO.error("Cuenta deshabilitada");
            }

            // Verificar bloqueo en Redis
            if (accountLockoutRedisService.isAccountLocked(user.getId())) {
                Duration remainingTime = accountLockoutRedisService.getRemainingLockoutTime(user.getId());
                return AuthResponseDTO.error(
                    String.format("Cuenta bloqueada temporalmente. Intenta nuevamente en %d minutos",
                        remainingTime.toMinutes()));
            }

            user.setPassword(passwordEncoder.encode(changePasswordDTO.newPassword()));
            user.setPasswordChangedAt(LocalDateTime.now());

            userRepository.save(user);

            log.info("Contraseña cambiada exitosamente para usuario: {}", user.getEmail());

            try {
                jwtSessionService.closeAllUserSessions(user.getId());
                log.info("TODAS las sesiones revocadas después de cambio de contraseña para: {}", username);
            } catch (Exception e) {
                log.warn("Error revocando sesiones después de cambio de contraseña: {}", e.getMessage());
            }

            try {
                emailService.sendPasswordChangedConfirmationEmail(user);
            } catch (Exception e) {
                log.warn("Error enviando email de confirmación: {}", e.getMessage());
            }

            return AuthResponseDTO.success(
                    "Contraseña cambiada exitosamente. Por seguridad, todas tus sesiones activas han sido cerradas.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al cambiar contraseña: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error inesperado al cambiar contraseña: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    /**
     * @deprecated Usar requestEmailChange() y verifyEmailChange() en su lugar
     *             Este método cambia el email inmediatamente sin verificar acceso
     *             al nuevo email (INSEGURO)
     */
    @Deprecated
    @Override
    @Transactional
    public AuthResponseDTO changeEmail(ChangeEmailDTO changeEmailDTO) {
        log.warn("DEPRECADO: Usar requestEmailChange() + verifyEmailChange() para mayor seguridad");

        // Redirigir al nuevo flujo seguro
        RequestEmailChangeDTO request = new RequestEmailChangeDTO(
                changeEmailDTO.newEmail(),
                changeEmailDTO.newEmailConfirmation(),
                changeEmailDTO.currentPassword());

        return requestEmailChange(request);
    }

    /**
     * Paso 1: Solicita cambio de email y envía código de verificación al NUEVO
     * email
     * Esto garantiza que el usuario tenga acceso al nuevo email antes de cambiar
     */
    @Override
    @Transactional
    public AuthResponseDTO requestEmailChange(RequestEmailChangeDTO requestEmailChangeDTO) {
        log.info("Procesando solicitud de cambio de email (Paso 1/2)");

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return AuthResponseDTO.error("Usuario no autenticado");
            }

            String currentEmail = authentication.getName();
            User user = userRepository.findByEmail(currentEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Validaciones
            String newEmail = requestEmailChangeDTO.newEmail().toLowerCase().trim();

            if (!requestEmailChangeDTO.emailsMatch()) {
                return AuthResponseDTO.error("Los correos electrónicos no coinciden");
            }

            if (newEmail.equals(currentEmail.toLowerCase())) {
                return AuthResponseDTO.error("El nuevo email debe ser diferente al actual");
            }

            if (!passwordEncoder.matches(requestEmailChangeDTO.currentPassword(), user.getPassword())) {
                log.warn("Intento de cambio de email con contraseña incorrecta para: {}", currentEmail);
                return AuthResponseDTO.error("Contraseña incorrecta");
            }

            if (userRepository.existsByEmail(newEmail)) {
                return AuthResponseDTO.error("El email ya está en uso");
            }

            // Verificar rate limiting
            if (!tokenRedisService.canRequestToken(user.getId(), "email_change")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            // Generar código y enviarlo al NUEVO email (no al actual)
            String verificationCode = tokenRedisService.generateAndStoreEmailChangeCode(user.getId(), newEmail);

            try {
                // IMPORTANTE: Enviar al NUEVO email para verificar que el usuario tiene acceso
                emailService.sendEmailChangeVerificationCode(newEmail, user.getName(), verificationCode);
                log.info("Código de verificación enviado al NUEVO email: {} para usuario: {}",
                        newEmail, currentEmail);
            } catch (Exception e) {
                log.error("Error enviando código de verificación al nuevo email: {}", e.getMessage());
                tokenRedisService.cancelEmailChange(user.getId());
                return AuthResponseDTO.error("Error enviando el código de verificación");
            }

            // Notificar al email actual sobre la solicitud
            try {
                emailService.sendEmailChangeRequestNotification(currentEmail, newEmail);
            } catch (Exception e) {
                log.warn("Error enviando notificación al email actual: {}", e.getMessage());
            }

            return AuthResponseDTO.success(
                    "Código de verificación enviado a " + maskEmail(newEmail) +
                            ". Verifica tu nuevo email e ingresa el código para confirmar el cambio.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al solicitar cambio de email: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error inesperado al solicitar cambio de email: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    /**
     * Paso 2: Verifica el código y confirma el cambio de email
     * Solo cambia el email si el código es válido
     */
    @Override
    @Transactional
    public AuthResponseDTO verifyEmailChange(VerifyEmailChangeDTO verifyEmailChangeDTO) {
        log.info("Procesando verificación de cambio de email (Paso 2/2)");

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return AuthResponseDTO.error("Usuario no autenticado");
            }

            String currentEmail = authentication.getName();
            User user = userRepository.findByEmail(currentEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Verificar y consumir código
            String newEmail = tokenRedisService.verifyAndConsumeEmailChangeCode(
                    user.getId(),
                    verifyEmailChangeDTO.verificationCode());

            if (newEmail == null) {
                log.warn("Código de cambio de email inválido o expirado para usuario: {}", currentEmail);
                return AuthResponseDTO.error("Código de verificación incorrecto o expirado");
            }

            // Verificar nuevamente que el email no esté en uso (por si acaso)
            if (userRepository.existsByEmail(newEmail)) {
                log.error("El email {} ya está en uso al momento de confirmar cambio", newEmail);
                return AuthResponseDTO.error("El email ya está en uso");
            }

            // Cambiar el email
            String oldEmail = user.getEmail();
            user.setEmail(newEmail);
            user.setEmailVerified(true); // Ya verificamos que tiene acceso al nuevo email

            userRepository.save(user);

            log.info("Email cambiado exitosamente de {} a {} para usuario ID: {}",
                    oldEmail, newEmail, user.getId());

            // Notificar al email anterior
            try {
                emailService.sendEmailChangedNotification(oldEmail, newEmail);
            } catch (Exception e) {
                log.warn("Error enviando notificación al email anterior: {}", e.getMessage());
            }

            // Cerrar todas las sesiones por seguridad
            try {
                jwtSessionService.closeAllUserSessions(user.getId());
                log.info("Todas las sesiones cerradas después de cambio de email para seguridad");
            } catch (Exception e) {
                log.warn("Error cerrando sesiones después de cambio de email: {}", e.getMessage());
            }

            return AuthResponseDTO.success(
                    "Email cambiado exitosamente a " + newEmail +
                            ". Por seguridad, todas tus sesiones han sido cerradas. Inicia sesión nuevamente.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al verificar cambio de email: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error inesperado al verificar cambio de email: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    /**
     * Enmascara un email para mostrar solo parcialmente
     * ejemplo@dominio.com -> e*****@dominio.com
     */
    private String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return email;
        }

        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];

        if (localPart.length() <= 2) {
            return localPart.charAt(0) + "*@" + domain;
        }

        return localPart.charAt(0) + "*****@" + domain;
    }

    // ============================================================================
    // GESTIÓN DE PERFIL
    // ============================================================================

    @Override
    @Transactional
    public AuthResponseDTO updateUserInfo(UpdateUserProfileDTO updateUserInfoDTO) {
        log.info("Procesando actualización de información de usuario");

        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return AuthResponseDTO.error("Usuario no autenticado");
            }

            String username = authentication.getName();
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            if (updateUserInfoDTO.name() == null || updateUserInfoDTO.name().trim().isEmpty()) {
                return AuthResponseDTO.error("El nombre es requerido");
            }

            if (updateUserInfoDTO.lastName() == null || updateUserInfoDTO.lastName().trim().isEmpty()) {
                return AuthResponseDTO.error("El apellido es requerido");
            }

            boolean hasChanges = false;

            if (!user.getName().equals(updateUserInfoDTO.name())) {
                user.setName(updateUserInfoDTO.name().trim());
                hasChanges = true;
            }

            if (!user.getLastName().equals(updateUserInfoDTO.lastName())) {
                user.setLastName(updateUserInfoDTO.lastName().trim());
                hasChanges = true;
            }

            if (updateUserInfoDTO.phoneNumber() != null &&
                    !updateUserInfoDTO.phoneNumber().equals(user.getPhoneNumber())) {
                user.setPhoneNumber(updateUserInfoDTO.phoneNumber().trim());
                user.setPhoneVerified(false);
                hasChanges = true;
            }

            if (!hasChanges) {
                return AuthResponseDTO.success("No hay cambios para actualizar");
            }

            userRepository.save(user);

            log.info("Información actualizada exitosamente para usuario: {}", user.getEmail());

            UserInfoDTO updatedInfo = UserInfoDTO.fromUser(user);

            return AuthResponseDTO.successWithUserInfo("Información actualizada exitosamente", updatedInfo);

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al actualizar información: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error inesperado al actualizar información: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserInfoDTO getCurrentUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("Usuario no autenticado");
        }

        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        return UserInfoDTO.fromUser(user);
    }

    // ============================================================================
    // VALIDACIÓN Y REFRESH DE TOKENS
    // ============================================================================

    @Override
    public TokenValidationDTO validateToken(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (token == null) {
                return TokenValidationDTO.invalid("Token no proporcionado");
            }

            JwtSessionService.SessionValidation validation = jwtSessionService.validateAccessToken(token);

            if (validation.isValid()) {
                String username = jwtUtil.extractUsername(token);
                Long remainingTime = jwtUtil.getTokenRemainingTime(token);

                User user = userRepository.findByEmail(username).orElse(null);
                if (user == null || !user.isEnabled() || 
                    accountLockoutRedisService.isAccountLocked(user.getId())) {
                    return TokenValidationDTO.invalid("Usuario no válido");
                }

                return TokenValidationDTO.valid(username, remainingTime);
            } else {
                return TokenValidationDTO.invalid(validation.getReason());
            }

        } catch (Exception e) {
            log.error("Error validando token: {}", e.getMessage());
            return TokenValidationDTO.invalid("Error validando token: " + e.getMessage());
        }
    }

    @Override
    public AuthResponseDTO refreshToken(RefreshTokenDTO refreshTokenDTO) {
        try {
            String refreshToken = refreshTokenDTO.refreshToken();

            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                log.warn("Intento de refresh con token vacío");
                return AuthResponseDTO.error("Refresh token no proporcionado");
            }

            JwtSessionService.SessionTokens newTokens = jwtSessionService.refreshAccessToken(refreshToken);

            String accessToken = newTokens.getAccessToken();
            String username = jwtUtil.extractUsername(accessToken);

            if (username == null) {
                log.warn("No se pudo extraer username del access token renovado");
                return AuthResponseDTO.error("Error al renovar tokens");
            }

            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + username));

            if (!user.isEnabled()) {
                log.warn("Intento de refresh token con usuario inactivo: {}", user.getEmail());
                return AuthResponseDTO.error("Usuario inactivo");
            }

            // Verificar bloqueo en Redis
            if (accountLockoutRedisService.isAccountLocked(user.getId())) {
                log.warn("Intento de refresh token con cuenta bloqueada: {}", user.getEmail());
                return AuthResponseDTO.error("Cuenta bloqueada");
            }

            UserInfoDTO userInfo = UserInfoDTO.fromUser(user);

            log.info("Tokens renovados exitosamente para usuario: {} - SessionId: {}",
                    user.getEmail(), newTokens.getSessionId());

            return AuthResponseDTO.success(
                    newTokens.getAccessToken(),
                    newTokens.getRefreshToken(),
                    newTokens.getExpiresIn() * 1000,
                    userInfo);

        } catch (RuntimeException e) {
            log.warn("Error en refresh token: {}", e.getMessage());
            return AuthResponseDTO.error(e.getMessage());
        } catch (Exception e) {
            log.error("Error inesperado en refresh token: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error al renovar tokens");
        }
    }

    // ============================================================================
    // MÉTODOS AUXILIARES PRIVADOS
    // ============================================================================

    /**
     * Crea una sesión completa para el usuario
     */
    /**
     * Crea una sesión completa para el usuario
     */
    private JwtSessionService.SessionTokens createUserSession(User user) {
        try {
            String userAgent = getCurrentUserAgent();
            String ipAddress = getCurrentIpAddress();

            log.info("Creando sesión para usuario: {} desde IP: {}", user.getEmail(), ipAddress);

            // Ajustado al orden correcto de parámetros: userId, email, userAgent, ipAddress
            JwtSessionService.SessionTokens sessionTokens = jwtSessionService.createSession(
                    user.getId(),
                    user.getEmail(),
                    userAgent,
                    ipAddress);

            log.info("Sesión creada exitosamente - SessionId: {}", sessionTokens.getSessionId());

            return sessionTokens;

        } catch (Exception e) {
            log.error("Error creando sesión para usuario {}: {}", user.getEmail(), e.getMessage(), e);
            throw new RuntimeException("Error al crear la sesión de usuario");
        }
    }

    /**
     * Log detallado del login exitoso
     */
    private void logLoginSuccess(User user, JwtSessionService.SessionTokens sessionTokens) {
        log.info("=== LOGIN EXITOSO ===");
        log.info("Usuario: {} (ID: {})", user.getEmail(), user.getId());
        log.info("Role: {}", user.getRole());
        log.info("SessionId: {}", sessionTokens.getSessionId());
        log.info("IP Address: {}", getCurrentIpAddress());
        log.info("User Agent: {}", getCurrentUserAgent());
        log.info("Access Token expira en: {} segundos", sessionTokens.getExpiresIn());
        log.info("====================");
    }

    /**
     * Obtiene el User-Agent actual
     */
    private String getCurrentUserAgent() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            return attributes.getRequest().getHeader("User-Agent");
        }
        return "Unknown";
    }

    /**
     * Obtiene la dirección IP del cliente
     */
    private String getCurrentIpAddress() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            HttpServletRequest request = attributes.getRequest();
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        }
        return "Unknown";
    }

    /**
     * Actualiza información del último login
     */
    private void updateLastLoginInfo(User user) {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .currentRequestAttributes();
            HttpServletRequest request = attributes.getRequest();

            String clientIp = getClientIpAddress(request);
            String userAgent = request.getHeader("User-Agent");

            user.updateLastLogin(clientIp, userAgent);

        } catch (Exception e) {
            log.warn("No se pudo obtener información del request para último login: {}", e.getMessage());
            user.setLastLogin(LocalDateTime.now());
        }
    }

    /**
     * Obtiene la dirección IP real del cliente
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String[] headers = {
                "X-Forwarded-For",
                "X-Real-IP",
                "Proxy-Client-IP",
                "WL-Proxy-Client-IP",
                "HTTP_X_FORWARDED_FOR",
                "HTTP_X_FORWARDED",
                "HTTP_X_CLUSTER_CLIENT_IP",
                "HTTP_CLIENT_IP",
                "HTTP_FORWARDED_FOR",
                "HTTP_FORWARDED",
                "HTTP_VIA",
                "REMOTE_ADDR"
        };

        for (String header : headers) {
            String ip = request.getHeader(header);
            if (org.springframework.util.StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    /**
     * Extrae el token del header Authorization
     */
    private String extractTokenFromHeader(String authHeader) {
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}