package com.e_commerce.e_commerce_back.services.implementation;

import com.e_commerce.e_commerce_back.dto.*;
import com.e_commerce.e_commerce_back.entity.User;
import com.e_commerce.e_commerce_back.exception.AccountAlreadyActiveException;
import com.e_commerce.e_commerce_back.exception.AccountLockedException;
import com.e_commerce.e_commerce_back.exception.AccountNotActivatedException;
import com.e_commerce.e_commerce_back.exception.EmailAlreadyExistsException;
import com.e_commerce.e_commerce_back.exception.EmailServiceException;
import com.e_commerce.e_commerce_back.exception.IdNumberAlreadyExistsException;
import com.e_commerce.e_commerce_back.exception.InvalidVerificationCodeException;
import com.e_commerce.e_commerce_back.exception.TooManyAttemptsException;
import com.e_commerce.e_commerce_back.exception.UnlockAccountException;
import com.e_commerce.e_commerce_back.exception.UserNotFoundException;
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

    private static final String MSG_UNLOCK_GENERIC = "Si el correo es válido y está bloqueado, recibirás un código";
    private static final String MSG_UNLOCK_SENT = "Código de desbloqueo enviado a tu email";
    private static final String MSG_UNLOCK_SUCCESS = "Cuenta desbloqueada exitosamente. Ya puedes iniciar sesión.";
    private static final String MSG_UNLOCK_ALREADY = "La cuenta ya está desbloqueada";
    private static final String MSG_RESET_GENERIC = "Si el correo es válido y está bloqueado, recibirás un código";
    private static final String MSG_RESET_SENT = "Código de desbloqueo enviado a tu email";

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
        String normalizedEmail = normalizeEmail(createUserDTO.email());
        log.info("Procesando registro para email: {}", normalizedEmail);

        // Validaciones (lanza excepciones específicas)
        validateEmailNotExists(normalizedEmail);
        validateIdNumberNotExists(createUserDTO.idNumber());

        // Crear y guardar usuario
        User newUser = buildNewUser(createUserDTO, normalizedEmail);
        User savedUser = userRepository.save(newUser);

        // Generar y enviar código de activación
        String activationCode = tokenRedisService.generateAndStoreActivationCode(savedUser.getId());
        sendActivationEmail(savedUser, activationCode);

        log.info("Usuario registrado exitosamente: {} - ID: {}", savedUser.getEmail(), savedUser.getId());

        return AuthResponseDTO.registered(
                "Usuario registrado exitosamente. Revisa tu email para activar tu cuenta con el código de 6 dígitos.");
    }

    @Override
    @Transactional
    public AuthResponseDTO activateAccount(ActivateAccountDTO activateAccountDTO) {
        log.info("Procesando activación de cuenta con código: {}", activateAccountDTO.activationCode());

        // ✨ Verificar código o lanzar excepción
        Long userId = verifyActivationCodeOrThrow(activateAccountDTO.activationCode());

        // ✨ Buscar usuario o lanzar excepción
        User user = findUserByIdOrThrow(userId);

        // ✨ Verificar si ya está activada
        checkIfAccountAlreadyActive(user);

        // ✨ Activar cuenta
        activateUserAccount(user);

        // ✨ Enviar email de bienvenida (no crítico)
        sendWelcomeEmailSafely(user);

        log.info("Cuenta activada exitosamente para usuario ID: {} - Email: {}", userId, user.getEmail());

        return AuthResponseDTO.success("¡Cuenta activada exitosamente! Ya puedes iniciar sesión.");
    }

    @Override
    public AuthResponseDTO resendActivationCode(String email) {
        String normalizedEmail = normalizeEmail(email);
        log.info("Procesando reenvío de código de activación para email: {}", normalizedEmail);

        User user = findUserByEmailOrThrow(normalizedEmail);

        checkIfAccountAlreadyActive(user);

        checkRateLimitOrThrow(user.getId(), "activation");

        String newActivationCode = tokenRedisService.generateAndStoreActivationCode(user.getId());
        log.info("Nuevo código de activación generado para usuario: {}", email);

        sendActivationEmailOrThrow(user, newActivationCode);

        log.info("Nuevo código de activación enviado para usuario: {}", email);

        return AuthResponseDTO.success("Nuevo código de activación enviado. Revisa tu email.");

    }

    // ============================================================================
    // METODOS AUXILIARES REGISTRO Y ACTIVACIÓN
    // ============================================================================

    /**
     * Metodo auxiliar para normalizar el email
     * 
     * @param email
     */
    private String normalizeEmail(String email) {
        return email.toLowerCase().trim();
    }

    /**
     * Metodo auxiliar para validar si el email ya existe
     * 
     * @param email
     */
    private void validateEmailNotExists(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException("El email ya está registrado");
        }
    }

    /**
     * Metodo auxiliar para validar si el número de identificación ya existe
     * 
     * @param idNumber
     */
    private void validateIdNumberNotExists(String idNumber) {
        if (userRepository.findByIdNumber(idNumber).isPresent()) {
            throw new IdNumberAlreadyExistsException("El número de identificación ya está registrado");
        }
    }

    /**
     * Metodo auxiliar para crear un nuevo usuario
     * 
     * @param dto
     * @param normalizedEmail
     * @return
     */
    private User buildNewUser(RegisterUserDTO dto, String normalizedEmail) {
        return User.builder()
                .idNumber(dto.idNumber())
                .name(dto.name())
                .lastName(dto.lastName())
                .email(normalizedEmail)
                .phoneNumber(dto.phoneNumber())
                .password(passwordEncoder.encode(dto.password()))
                .dateOfBirth(dto.dateOfBirth())
                .role(EnumRole.USER)
                .status(EnumStatus.INACTIVE)
                .emailVerified(false)
                .phoneVerified(false)
                .build();
    }

    /**
     * Metodo auxiliar para enviar el email de activación
     * 
     * @param user
     * @param code
     */
    private void sendActivationEmail(User user, String code) {
        try {
            emailService.sendActivationEmail(user, code);
            log.info("Email de activación enviado a: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Error enviando email de activación a {}: {}", user.getEmail(), e.getMessage());
            // No lanzar excepción - el usuario ya está registrado
        }
    }

    /**
     * Verifica el código de activación y lo consume
     * 
     * @throws InvalidVerificationCodeException si el código es inválido o expirado
     */
    private Long verifyActivationCodeOrThrow(String activationCode) {
        Long userId = tokenRedisService.verifyAndConsumeActivationCode(activationCode);

        if (userId == null) {
            log.warn("Código de activación inválido o expirado");
            throw new InvalidVerificationCodeException("Código de activación incorrecto o expirado");
        }

        return userId;
    }

    /**
     * Busca un usuario por ID
     * 
     * @throws UserNotFoundException si no se encuentra
     */
    private User findUserByIdOrThrow(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("Usuario no encontrado con ID: " + userId));
    }

    /**
     * Verifica si la cuenta ya está activada
     * 
     * @throws AccountAlreadyActiveException si ya está activa
     */
    private void checkIfAccountAlreadyActive(User user) {
        // Puedes usar el método que ya existe en User
        if (user.isEnabled()) {
            log.info("La cuenta del usuario {} ya está activada", user.getEmail());
            throw new AccountAlreadyActiveException("La cuenta ya está activada");
        }
    }

    /**
     * Verifica si la cuenta está activada
     * 
     * @throws AccountNotActivatedException si no está activada
     */
    private void checkAccountActivated(User user) {
        if (!user.isEnabled()) {
            throw new AccountNotActivatedException(
                    "Cuenta no activada. Verifica tu email.");
        }
    }

    /**
     * Activa la cuenta del usuario
     */
    private void activateUserAccount(User user) {
        log.info("Estado antes de activar - Status: {}, EmailVerified: {}",
                user.getStatus(), user.getEmailVerified());

        user.setStatus(EnumStatus.ACTIVE);
        user.setEmailVerified(true);

        User savedUser = userRepository.save(user);

        log.info("Estado después de activar - Status: {}, EmailVerified: {}, isEnabled: {}",
                savedUser.getStatus(), savedUser.getEmailVerified(), savedUser.isEnabled());
    }

    /**
     * Envía email de bienvenida sin lanzar excepción si falla
     */
    private void sendWelcomeEmailSafely(User user) {
        try {
            emailService.sendWelcomeEmail(user);
            log.info("Email de bienvenida enviado a: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Error enviando email de bienvenida a {}: {}", user.getEmail(), e.getMessage());
            // No lanzar excepción - la activación ya fue exitosa
        }
    }

    /**
     * Verifica si se ha excedido el límite de intentos
     * 
     * @throws TooManyAttemptsException si se ha excedido el límite
     */
    private void checkRateLimitOrThrow(Long userId, String tokenType) {
        if (!tokenRedisService.canRequestToken(userId, tokenType)) {
            throw new TooManyAttemptsException("Demasiadas solicitudes. Intenta en 1 hora", 3600);
        }
    }

    /**
     * Envía email de activación
     * 
     * @throws EmailServiceException si hay error al enviar el email
     */
    private void sendActivationEmailOrThrow(User user, String code) {
        try {
            emailService.sendActivationEmail(user, code);
            log.info("Email de activación enviado a: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Error enviando email de activación a {}: {}",
                    user.getEmail(), e.getMessage(), e); // ⭐ Agregar excepción completa
            throw new EmailServiceException("Error enviando el email de activación", e);
        }
    }

    /**
     * Busca un usuario por email
     * 
     * @throws UserNotFoundException si no se encuentra
     */
    private User findUserByEmailOrThrow(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Usuario no encontrado con email: " + email));
    }

    // ============================================================================
    // LOGIN Y LOGOUT
    // ============================================================================

    @Override
    public AuthResponseDTO login(LoginDTO loginDTO) {
        String normalizedEmail = normalizeEmail(loginDTO.email());
        log.info("Procesando login para email: {}", normalizedEmail);

        User user = findUserByEmailOrThrow(normalizedEmail);

        checkAccountLockout(user, normalizedEmail);
        checkAccountActivated(user);

        validatePasswordOrThrow(loginDTO.password(), user, normalizedEmail);

        // Autenticación exitosa
        return createSuccessfulLoginResponse(user);
    }

    @Override
    public void logout(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (!StringUtils.hasText(token)) {
                log.info("Logout procesado sin token válido");
                return;
            }

            processTokenLogout(token);

        } catch (Exception e) {
            log.error("Error inesperado en logout: {}", e.getMessage(), e);
        } finally {
            // Siempre limpiar el contexto de seguridad
            SecurityContextHolder.clearContext();
        }
    }

    // ============================================================================
    // METODOS AUXILIARES LOGIN Y LOGOUT
    // ============================================================================

    /**
     * Procesa el logout del token: cierra sesión o blacklist
     */
    private void processTokenLogout(String token) {
        try {
            String sessionId = jwtSessionService.findSessionIdByAccessToken(token);

            if (sessionId != null) {
                closeSessionGracefully(sessionId);
            } else {
                blacklistTokenWithLogging(token, "Sesión no encontrada");
            }

        } catch (Exception e) {
            log.warn("Token inválido durante logout: {}", e.getMessage());
            blacklistTokenWithLogging(token, "Token inválido");
        }
    }

    /**
     * Cierra sesión de forma segura
     */
    private void closeSessionGracefully(String sessionId) {
        try {
            jwtSessionService.closeSession(sessionId);
            log.info("✓ Sesión cerrada exitosamente - SessionId: {}", sessionId);
        } catch (Exception e) {
            log.error("Error cerrando sesión {}: {}", sessionId, e.getMessage(), e);
            // No relanzar - el logout debe completarse
        }
    }

    /**
     * Blacklistea token con logging apropiado
     */
    private void blacklistTokenWithLogging(String token, String reason) {
        try {
            jwtSessionService.blacklistAccessToken(token);
            log.info("✓ Token blacklisted - Razón: {}", reason);
        } catch (Exception e) {
            log.error("Error blacklisteando token: {}", e.getMessage(), e);
            // No relanzar - el logout debe completarse
        }
    }

    /**
     * Crea una respuesta exitosa para el login
     */
    private AuthResponseDTO createSuccessfulLoginResponse(User user) {
        handleSuccessfulLogin(user);
        JwtSessionService.SessionTokens sessionTokens = createUserSession(user);
        logLoginSuccess(user, sessionTokens);
        UserInfoDTO userInfo = UserInfoDTO.fromUser(user);
        return AuthResponseDTO.success(
                sessionTokens.getAccessToken(),
                sessionTokens.getRefreshToken(),
                sessionTokens.getExpiresIn() * 1000,
                userInfo);
    }

    /**
     * Valida la contraseña del usuario
     */
    private void validatePasswordOrThrow(String password, User user, String email) {
        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("Contraseña incorrecta para usuario: {}", email);
            handleFailedLogin(user, email);
            // handleFailedLogin ya lanza InvalidCredentialsException o
            // BadCredentialsException
        }
    }

    /**
     * Verifica si la cuenta está bloqueada y lanza excepción si es necesario
     */
    private void checkAccountLockout(User user, String email) {
        if (accountLockoutRedisService.isAccountLocked(user.getId())) {
            Duration remainingTime = accountLockoutRedisService.getRemainingLockoutTime(user.getId());
            long remainingMinutes = remainingTime.toMinutes();

            log.warn("Intento de login OAuth en cuenta bloqueada: {} - Tiempo restante: {} minutos",
                    email, remainingMinutes);

            throw new AccountLockedException(
                    String.format("Cuenta temporalmente bloqueada. Intenta nuevamente en %d minutos",
                            remainingMinutes),
                    remainingMinutes);
        }
    }

    // ============================================================================
    // MANEJO DE INTENTOS FALLIDOS
    // ============================================================================

    /**
     * Maneja un intento fallido de login registrando el intento y lanzando la
     * excepción apropiada
     * 
     * @param user  Usuario que intentó hacer login
     * @param email Email usado en el intento (para logging)
     * @throws AccountLockedException  si la cuenta está bloqueada
     * @throws BadCredentialsException si las credenciales son incorrectas
     */
    private void handleFailedLogin(User user, String email) {
        log.warn("Intento fallido de login para usuario: {}", email);

        Long userId = user.getId();
        int failedAttempts = accountLockoutRedisService.recordFailedAttempt(userId);

        // Verificar bloqueo y lanzar excepción si aplica
        checkAccountLockoutAndThrow(userId, email, failedAttempts);

        // Si llegamos aquí, no está bloqueada - informar intentos restantes
        throwBadCredentialsWithRemainingAttempts(userId, failedAttempts);
    }

    /**
     * Verifica si la cuenta está bloqueada y lanza excepción correspondiente
     */
    private void checkAccountLockoutAndThrow(Long userId, String email, int failedAttempts) {
        if (!accountLockoutRedisService.isAccountLocked(userId)) {
            return; // No está bloqueada, continuar
        }

        Duration remainingTime = accountLockoutRedisService.getRemainingLockoutTime(userId);
        long minutes = remainingTime.toMinutes();

        log.error("Cuenta bloqueada - Usuario: {} - Intentos: {} - Tiempo restante: {} min",
                email, failedAttempts, minutes);

        throw new AccountLockedException(
                String.format("Cuenta bloqueada por %d minutos debido a múltiples intentos fallidos", minutes),
                minutes);
    }

    /**
     * Lanza excepción de credenciales incorrectas con intentos restantes
     */
    private void throwBadCredentialsWithRemainingAttempts(Long userId, int failedAttempts) {
        int remainingAttempts = accountLockoutRedisService.getRemainingAttempts(userId);

        log.warn("Credenciales inválidas - Intentos fallidos: {} - Restantes: {}",
                failedAttempts, remainingAttempts);

        throw new BadCredentialsException(
                String.format("Email o contraseña incorrectos. Intentos restantes: %d", remainingAttempts));
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

    // ============================================================================
    // DESBLOQUEO INMEDIATO - OPTIMIZADO
    // ============================================================================

    @Override
    public AuthResponseDTO requestImmediateUnlock(RequestImmediateUnlockDTO requestImmediateUnlockDTO) {
        String normalizedEmail = normalizeEmail(requestImmediateUnlockDTO.email());

        // Buscar usuario - retornar mensaje genérico si no existe (seguridad)
        User user = userRepository.findByEmail(normalizedEmail).orElse(null);
        if (user == null) {
            log.info("Intento de desbloqueo con email no registrado: {}", normalizedEmail);
            return AuthResponseDTO.success(MSG_UNLOCK_GENERIC);
        }

        // Verificar si está bloqueado
        if (!accountLockoutRedisService.isAccountLocked(user.getId())) {
            log.info("Intento de desbloqueo de cuenta no bloqueada: {}", normalizedEmail);
            return AuthResponseDTO.success(MSG_UNLOCK_GENERIC);
        }

        // Verificar rate limit
        checkRateLimitOrThrow(user.getId(), "unlock");

        // Generar y enviar código
        String unlockCode = tokenRedisService.generateAndStoreUnlockCode(user.getId());
        sendUnlockCodeOrThrow(user, unlockCode);

        log.info("Código de desbloqueo enviado a usuario: {}", user.getEmail());
        return AuthResponseDTO.success(MSG_UNLOCK_SENT);
    }

    /**
     * Envía código de desbloqueo
     * 
     * @throws EmailServiceException si hay error al enviar el email
     */
    private void sendUnlockCodeOrThrow(User user, String code) {
        try {
            emailService.sendUnlockCode(user, code);
            log.info("Email de desbloqueo enviado a: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Error enviando email de desbloqueo a {}: {}", user.getEmail(), e.getMessage(), e);
            throw new EmailServiceException("Error enviando el código de desbloqueo", e);
        }
    }

    @Override
    @Transactional
    public AuthResponseDTO verifyUnlockCode(VerifyUnlockCodeDTO verifyUnlockCodeDTO) {
        log.info("Procesando verificación de código de desbloqueo");

        // Verificar y consumir código
        Long userId = verifyUnlockCodeOrThrow(verifyUnlockCodeDTO.code());

        // Buscar usuario
        User user = findUserByIdOrThrow(userId);

        // Verificar si ya está desbloqueada
        if (!accountLockoutRedisService.isAccountLocked(userId)) {
            log.info("La cuenta del usuario {} ya está desbloqueada", user.getEmail());
            return AuthResponseDTO.success(MSG_UNLOCK_ALREADY);
        }

        // Desbloquear cuenta
        unlockUserAccount(userId, user.getEmail());

        // Enviar email de confirmación (no crítico)
        sendAccountUnlockedEmailSafely(user);

        return AuthResponseDTO.success(MSG_UNLOCK_SUCCESS);
    }

    /**
     * Verifica el código de desbloqueo y lo consume
     * 
     * @throws InvalidVerificationCodeException si el código es inválido o expirado
     */
    private Long verifyUnlockCodeOrThrow(String unlockCode) {
        Long userId = tokenRedisService.verifyAndConsumeUnlockCode(unlockCode);

        if (userId == null) {
            log.warn("Código de desbloqueo inválido o expirado");
            throw new InvalidVerificationCodeException("Código de desbloqueo incorrecto o expirado");
        }

        return userId;
    }

    /**
     * Desbloquea la cuenta del usuario en Redis
     */
    private void unlockUserAccount(Long userId, String email) {
        try {
            accountLockoutRedisService.unlockAccount(userId);
            log.info("✓ Cuenta desbloqueada exitosamente - UserId: {} - Email: {}", userId, email);
        } catch (Exception e) {
            log.error("Error desbloqueando cuenta {}: {}", userId, e.getMessage(), e);
            throw new UnlockAccountException("Error al desbloquear la cuenta", e);
        }
    }

    /**
     * Envía email de confirmación de desbloqueo sin lanzar excepción si falla
     */
    private void sendAccountUnlockedEmailSafely(User user) {
        try {
            emailService.sendAccountUnlockedEmail(user);
            log.info("Email de confirmación de desbloqueo enviado a: {}", user.getEmail());
        } catch (Exception e) {
            log.warn("Error enviando email de confirmación de desbloqueo a {}: {}",
                    user.getEmail(), e.getMessage());
            // No lanzar excepción - el desbloqueo ya fue exitoso
        }
    }

    @Transactional
    public void unlockUserAccount(String email) {
        String normalizedEmail = normalizeEmail(email);
        User user = findUserByEmailOrThrow(normalizedEmail);

        // Desbloquear en Redis
        accountLockoutRedisService.unlockAccount(user.getId());

        log.info("Cuenta desbloqueada manualmente para usuario: {} (Redis)", normalizedEmail);
    }

    // ============================================================================
    // RECUPERACIÓN DE CONTRASEÑA
    // ============================================================================

    @Override
    public AuthResponseDTO forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {
        String normalizedEmail = normalizeEmail(forgotPasswordDTO.email());

        // Buscar usuario - retornar mensaje genérico si no existe (seguridad)
        User user = userRepository.findByEmail(normalizedEmail).orElse(null);

        if (user == null) {
            log.info("Intento de reset para email no registrado: {}", normalizedEmail);
            return AuthResponseDTO.success(MSG_RESET_GENERIC);
        }

        // Verificar rate limit
        checkRateLimitOrThrow(user.getId(), "reset");

        // Generar y enviar código
        String resetCode = tokenRedisService.generateAndStoreResetCode(user.getId());
        sendPasswordResetEmailOrThrow(user, resetCode);

        log.info("Código de reset enviado a: {}", normalizedEmail);
        return AuthResponseDTO.success(MSG_RESET_SENT);
    }

    /**
     * Envía email de reseteo de contraseña
     * 
     * @throws EmailServiceException si hay error al enviar el email
     */
    private void sendPasswordResetEmailOrThrow(User user, String code) {
        try {
            emailService.sendPasswordResetEmail(user, code);
            log.info("Email de reset enviado a: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Error enviando email de reset a {}: {}", user.getEmail(), e.getMessage(), e);
            throw new EmailServiceException("Error enviando el código de reseteo", e);
        }
    }

    private void verifyPasswordMatchOrThrow(ResetPasswordDTO resetPasswordDTO) {
        if (!resetPasswordDTO.passwordsMatch()) {
            throw new InvalidVerificationCodeException("Las contraseñas no coinciden");
        }
    }

    @Override
    @Transactional
    public AuthResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO) {
        log.info("Procesando reseteo de contraseña");

        try {
            Long userId = verifyResetCodeOrThrow(resetPasswordDTO.resetCode());

            User user = findUserByIdOrThrow(userId);

            verifyPasswordMatchOrThrow(resetPasswordDTO);

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

    /**
     * Verifica el código de reseteo y lo consume
     * 
     * @throws InvalidVerificationCodeException si el código es inválido o expirado
     */
    private Long verifyResetCodeOrThrow(String resetCode) {
        Long userId = tokenRedisService.verifyAndConsumeResetCode(resetCode);

        if (userId == null) {
            log.warn("Código de reseteo inválido o expirado");
            throw new InvalidVerificationCodeException("Código de reseteo incorrecto o expirado");
        }

        return userId;
    }

    @Override
    public AuthResponseDTO resendResetCode(ResendresetCodeDTO resendresetCodeDTO) {
        String normalizedEmail = resendresetCodeDTO.email().toLowerCase().trim();
        log.info("Procesando reenvío de código de reseteo para email: {}", normalizedEmail);

        try {
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            if (!tokenRedisService.canRequestToken(user.getId(), "reset")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            String newResetCode = tokenRedisService.generateAndStoreResetCode(user.getId());
            log.info("Nuevo código de reseteo generado para usuario: {}", normalizedEmail);

            try {
                emailService.sendPasswordResetEmail(user, newResetCode);
                log.info("Nuevo email de reseteo enviado a: {}", normalizedEmail);
            } catch (Exception e) {
                log.error("Error enviando nuevo email de reseteo a {}: {}",
                        user.getEmail(), e.getMessage());
                return AuthResponseDTO.error("Error enviando el email de reseteo");
            }

            return AuthResponseDTO.success("Nuevo código de reseteo enviado. Revisa tu email.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de reenvío con email no registrado: {}", normalizedEmail);
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error en reenvío para email: {}, error: {}", normalizedEmail, e.getMessage());
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