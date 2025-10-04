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

import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Implementación del servicio de autenticación
 * Maneja login, registro y operaciones JWT con seguridad mejorada
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;

    @Value("${app.jwt.expiration}")
    private Long jwtExpiration;

    @Value("${app.security.max-failed-attempts:5}")
    private Integer maxFailedAttempts;

    @Value("${app.security.lockout-duration-minutes:15}")
    private Integer lockoutDurationMinutes;

    private final TokenRedisService tokenRedisService;
    private final JwtSessionService jwtSessionService;

    /**
     * Implementación del servicio de autenticación
     * Maneja login, registro y operaciones JWT con seguridad mejorada
     */

    @Override
    public AuthResponseDTO register(RegisterUserDTO createUserDTO) {
        String normalizedEmail = createUserDTO.email().toLowerCase().trim();
        log.info("Procesando registro para email: {}", normalizedEmail);

        try {
            // Verificar si el email ya existe
            if (userRepository.existsByEmail(normalizedEmail)) {
                throw new EmailIsExists("El email ya está registrado");
            }

            // Verificar si el número de identificación ya existe
            if (userRepository.findByIdNumber(createUserDTO.idNumber()).isPresent()) {
                throw new IdNumberIsExists("El número de identificación ya está registrado");
            }

            // Usar el builder mejorado de User
            User newUser = User.builder()
                    .idNumber(createUserDTO.idNumber())
                    .name(createUserDTO.name())
                    .lastName(createUserDTO.lastName())
                    .email(normalizedEmail) // Normalizar email
                    .phoneNumber(createUserDTO.phoneNumber())
                    .password(passwordEncoder.encode(createUserDTO.password()))
                    .dateOfBirth(createUserDTO.dateOfBirth()) // Si está disponible en el DTO
                    .role(EnumRole.USER)
                    .status(EnumStatus.INACTIVE) // Requiere activación por email
                    .emailVerified(false)
                    .phoneVerified(false)
                    .failedLoginAttempts(0)
                    .build();

            // Guardar usuario
            User savedUser = userRepository.save(newUser);

            String activationCode = tokenRedisService.generateAndStoreActivationCode(savedUser.getId());

            log.info("Usuario registrado exitosamente: {} - ID: {}",
                    savedUser.getEmail(), savedUser.getId());

            // Enviar email de activación
            try {
                emailService.sendActivationEmail(savedUser, activationCode);
                log.info("Email de activación enviado a: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Error enviando email de activación a {}: {}",
                        savedUser.getEmail(), e.getMessage());
                // No fallar el registro si el email falla
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
            // Verificar y consumir el código de activación
            Long userId = tokenRedisService.verifyAndConsumeActivationCode(activateAccountDTO.activationCode());

            if (userId == null) {
                log.warn("Código de activación inválido o expirado");
                return AuthResponseDTO.error("Código de activación incorrecto o expirado");
            }

            // Buscar usuario por ID
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con ID: " + userId));

            // Verificar si la cuenta ya está activada
            if (user.getStatus() == EnumStatus.ACTIVE && Boolean.TRUE.equals(user.getEmailVerified())) {
                log.info("La cuenta del usuario {} ya está activada", user.getEmail());
                return AuthResponseDTO.error("La cuenta ya está activada");
            }

            // Log del estado antes de activar
            log.info("Estado antes de activar - Status: {}, EmailVerified: {}",
                    user.getStatus(), user.getEmailVerified());

            // Activar la cuenta
            user.setStatus(EnumStatus.ACTIVE);
            user.setEmailVerified(true);

            // Guardar cambios y forzar flush
            User savedUser = userRepository.save(user);
            userRepository.flush(); // Forzar la escritura en la BD

            // Log del estado después de activar
            log.info("Estado después de activar - Status: {}, EmailVerified: {}, isEnabled: {}",
                    savedUser.getStatus(), savedUser.getEmailVerified(), savedUser.isEnabled());

            log.info("Cuenta activada exitosamente para usuario ID: {} - Email: {}",
                    userId, savedUser.getEmail());

            // Enviar email de bienvenida
            try {
                emailService.sendWelcomeEmail(savedUser);
                log.info("Email de bienvenida enviado a: {}", savedUser.getEmail());
            } catch (Exception e) {
                log.error("Error enviando email de bienvenida a {}: {}", savedUser.getEmail(), e.getMessage());
                // No fallar la activación si falla el email
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

    /**
     * Implementación del servicio de login
     * Maneja el login de un usuario con seguridad mejorada
     */

    @Override
    @Transactional // IMPORTANTE: Agregar esta anotación
    public AuthResponseDTO login(LoginDTO loginDTO) {
        String normalizedEmail = loginDTO.email().toLowerCase().trim();
        log.info("Procesando login para email: {}", normalizedEmail);

        try {
            // Buscar usuario primero para verificar bloqueos
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Verificar si la cuenta está temporalmente bloqueada
            if (user.isAccountTemporarilyLocked()) {
                log.warn("Intento de login en cuenta bloqueada: {}", loginDTO.email());
                throw new BadCredentialsException("Cuenta temporalmente bloqueada por múltiples intentos fallidos");
            }

            // Verificar que el usuario esté habilitado
            if (!user.isEnabled()) {
                throw new BadCredentialsException("Cuenta no activada. Verifica tu email.");
            }

            try {
                // Autenticar usuario
                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                normalizedEmail,
                                loginDTO.password()));

                // Login exitoso - resetear intentos fallidos
                user.resetFailedLoginAttempts();

                // Actualizar información de último login con contexto de request
                updateLastLoginInfo(user);

                // Guardar cambios del usuario
                userRepository.save(user);

                // Obtener detalles del usuario autenticado
                UserDetails userDetails = (UserDetails) authentication.getPrincipal();

                // ========== CREAR SESIÓN COMPLETA ==========
                String userAgent = getCurrentUserAgent();
                String ipAddress = getCurrentIpAddress();

                JwtSessionService.SessionTokens sessionTokens = jwtSessionService.createSession(
                        user.getId(),
                        user.getEmail(),
                        userAgent,
                        ipAddress);

                log.info("=====================================================");
                log.info("LOGIN EXITOSO PARA: {}", user.getEmail());
                log.info("ACCESS TOKEN: {}", sessionTokens.getAccessToken());
                log.info("REFRESH TOKEN: {}", sessionTokens.getRefreshToken());
                log.info("SESSION ID: {}", sessionTokens.getSessionId());
                log.info("EXPIRACIÓN: {} segundos", sessionTokens.getExpiresIn());
                log.info("=====================================================");

                UserInfoDTO userInfo = UserInfoDTO.fromUser(user);

                log.info("Login exitoso para usuario: {} - IP: {} - SessionId: {}",
                        user.getEmail(),
                        ipAddress,
                        sessionTokens.getSessionId());

                return AuthResponseDTO.success(
                        sessionTokens.getAccessToken(),
                        sessionTokens.getRefreshToken(),
                        sessionTokens.getExpiresIn() * 1000,
                        userInfo);

            } catch (BadCredentialsException e) {
                // IMPORTANTE: Manejar los intentos fallidos aquí
                return handleFailedLoginAttempt(user, loginDTO.email());
            }

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

    /**
     * Método separado para manejar intentos fallidos de login
     * Usa REQUIRES_NEW para crear una transacción independiente que no haga
     * rollback
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    private AuthResponseDTO handleFailedLoginAttempt(User user, String email) {
        // Recargar el usuario desde la BD para obtener el valor más actualizado
        User freshUser = userRepository.findById(user.getId())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        log.info("DEBUG - Intentos fallidos ACTUALES en BD: {}", freshUser.getFailedLoginAttempts());

        // Incrementar intentos fallidos
        freshUser.incrementFailedLoginAttempts();

        log.info("DEBUG - Intentos fallidos DESPUÉS de incrementar: {}", freshUser.getFailedLoginAttempts());

        // Verificar si se debe bloquear la cuenta
        if (freshUser.getFailedLoginAttempts() >= maxFailedAttempts) {
            freshUser.lockAccount(lockoutDurationMinutes);
            userRepository.saveAndFlush(freshUser);

            log.warn("Cuenta bloqueada por {} intentos fallidos: {} - Bloqueado hasta: {}",
                    maxFailedAttempts, email, freshUser.getAccountLockedUntil());

            throw new BadCredentialsException(
                    String.format("Cuenta bloqueada por %d minutos debido a múltiples intentos fallidos",
                            lockoutDurationMinutes));
        }

        // Guardar y forzar flush a la BD
        userRepository.saveAndFlush(freshUser);

        // Verificar que se guardó correctamente
        User verifiedUser = userRepository.findById(freshUser.getId()).orElse(freshUser);
        log.info("DEBUG - Intentos fallidos VERIFICADOS en BD: {}", verifiedUser.getFailedLoginAttempts());

        int remainingAttempts = maxFailedAttempts - freshUser.getFailedLoginAttempts();

        log.warn("Credenciales inválidas para email: {} - Intentos fallidos: {} - Intentos restantes: {}",
                email, freshUser.getFailedLoginAttempts(), remainingAttempts);

        throw new BadCredentialsException(
                String.format("Email o contraseña incorrectos. Intentos restantes: %d",
                        remainingAttempts));
    }

    // Métodos auxiliares para obtener información del request
    private String getCurrentUserAgent() {
        // Implementación para obtener User-Agent del request
        // Ejemplo con ServletRequestAttributes
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes != null) {
            return attributes.getRequest().getHeader("User-Agent");
        }
        return "Unknown";
    }

    private String getCurrentIpAddress() {
        // Implementación para obtener IP del request
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
     * Implementación del servicio de validación de token
     * Maneja la validación de un token JWT con seguridad mejorada
     */

    @Override
    public TokenValidationDTO validateToken(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (token == null) {
                return TokenValidationDTO.invalid("Token no proporcionado");
            }

            // ✅ CAMBIO: Usar JwtSessionService para validación completa
            JwtSessionService.SessionValidation validation = jwtSessionService.validateAccessToken(token);

            if (validation.isValid()) {
                String username = jwtUtil.extractUsername(token);
                Long remainingTime = jwtUtil.getTokenRemainingTime(token);

                // Verificar que el usuario aún esté habilitado
                User user = userRepository.findByEmail(username).orElse(null);
                if (user == null || !user.isEnabled() || user.isAccountTemporarilyLocked()) {
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

    /**
     * Implementación del servicio de obtención de información del usuario actual
     * Maneja la obtención de información del usuario autenticado con seguridad
     * mejorada
     */

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

        // Usar el método factory para consistencia
        return UserInfoDTO.fromUser(user);
    }

    /**
     * Implementación del servicio de logout
     * Maneja el cierre de sesión de un usuario con seguridad mejorada
     */

    // Entonces tu logout se simplifica:
    @Override
    public void logout(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (token != null) {
                try {
                    // ✅ BUSCAR Y CERRAR SESIÓN DIRECTAMENTE
                    String sessionId = jwtSessionService.findSessionIdByAccessToken(token);

                    if (sessionId != null) {
                        jwtSessionService.closeSession(sessionId);
                        log.info("Sesión cerrada - SessionId: {}", sessionId);
                    } else {
                        // Fallback: blacklist del token
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

    /**
     * Extrae el token del header Authorization
     */

    private String extractTokenFromHeader(String authHeader) {
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Actualiza la información del último login con contexto HTTP
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
     * Obtiene la IP real del cliente considerando proxies y load balancers
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
            if (StringUtils.hasText(ip) && !"unknown".equalsIgnoreCase(ip)) {
                // Si hay múltiples IPs separadas por coma, tomar la primera
                if (ip.contains(",")) {
                    ip = ip.split(",")[0].trim();
                }
                return ip;
            }
        }

        return request.getRemoteAddr();
    }

    /**
     * Método para desbloquear manualmente una cuenta (útil para administradores)
     */

    @Transactional
    public void unlockUserAccount(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

        user.resetFailedLoginAttempts();
        userRepository.save(user);

        log.info("Cuenta desbloqueada manualmente para usuario: {}", normalizedEmail);
    }

    /**
     * Implementación del servicio de reenvío de código de activación
     */

    @Override
    public AuthResponseDTO resendActivationCode(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        log.info("Procesando reenvío de código de activación para email: {}", normalizedEmail);

        try {
            // Buscar usuario por email
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Verificar si la cuenta ya está activada
            if (user.isEnabled()) {
                return AuthResponseDTO.error("La cuenta ya está activada");
            }

            // ✅ AGREGAR RATE LIMITING:
            if (!tokenRedisService.canRequestToken(user.getId(), "activation")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            String newActivationCode = tokenRedisService.generateAndStoreActivationCode(user.getId());
            log.info("Nuevo código de activación generado para usuario: {}", email);

            // Enviar nuevo email de activación
            try {
                emailService.sendActivationEmail(user, newActivationCode);
                log.info("Nuevo email de activación enviado a: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Error enviando nuevo email de activación a {}: {}",
                        user.getEmail(), e.getMessage());
                return AuthResponseDTO.error("Error enviando el email de activación");
            }

            return AuthResponseDTO.success(
                    "Nuevo código de activación enviado. Revisa tu email.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de reenvío con email no registrado: {}", normalizedEmail);
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error en reenvío para email: {}, error: {}", normalizedEmail, e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    /**
     * Implementación del servicio de olvido de contraseña
     */

    @Override
    public AuthResponseDTO forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {
        String normalizedEmail = forgotPasswordDTO.email().toLowerCase().trim();
        try {
            User user = userRepository.findByEmail(normalizedEmail)
                    .orElseThrow(() -> new UsernameNotFoundException(
                            "Usuario no encontrado con el email: " + normalizedEmail));

            // ✅ AGREGAR RATE LIMITING:
            if (!tokenRedisService.canRequestToken(user.getId(), "reset")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            String resetCode = tokenRedisService.generateAndStoreResetCode(user.getId());

            emailService.sendPasswordResetEmail(user, resetCode);

            log.info("Código de reseteo de contraseña enviado a: {}", normalizedEmail);
            return AuthResponseDTO.success("Se ha enviado un código de reseteo a tu correo electrónico.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de reseteo de contraseña para email no registrado: {}", normalizedEmail);
            // Por seguridad, no revelamos si el email existe o no.
            return AuthResponseDTO.success("Si tu correo está registrado, recibirás un código de reseteo.");
        } catch (Exception e) {
            log.error("Error al procesar la solicitud de olvido de contraseña para {}: {}", normalizedEmail,
                    e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor al intentar resetear la contraseña.");
        }
    }

    /**
     * Implementación del servicio de reseteo de contraseña
     * Usa el código de Redis para obtener el userId directamente
     */

    @Override
    @Transactional
    public AuthResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO) {
        log.info("Procesando reseteo de contraseña");

        try {
            // Verificar y consumir el código de reset
            Long userId = tokenRedisService.verifyAndConsumeResetCode(resetPasswordDTO.resetCode());

            if (userId == null) {
                log.warn("Código de reset inválido o expirado");
                return AuthResponseDTO.error("Código de reset incorrecto o expirado");
            }

            // Buscar usuario por ID
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con ID: " + userId));

            // Validar que las contraseñas coincidan
            if (!resetPasswordDTO.passwordsMatch()) {
                return AuthResponseDTO.error("Las contraseñas no coinciden");
            }

            // Validar longitud mínima de contraseña (por si acaso)
            if (resetPasswordDTO.password().length() < 8) {
                return AuthResponseDTO.error("La contraseña debe tener al menos 8 caracteres");
            }

            // ✅ MEJORA: Actualizar contraseña y timestamp
            user.setPassword(passwordEncoder.encode(resetPasswordDTO.password()));
            user.setPasswordChangedAt(LocalDateTime.now());

            // Resetear intentos fallidos por seguridad
            user.resetFailedLoginAttempts();

            userRepository.save(user);

            log.info("Contraseña restablecida exitosamente para usuario ID: {} - Email: {}",
                    userId, user.getEmail());

            // Opcional: Enviar email de confirmación
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
     * Implementación del servicio de refresco de token
     */

    /**
     * Implementación del servicio de cambio de contraseña
     */

    @Override
    @Transactional
    public AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO) {
        log.info("Procesando cambio de contraseña");

        try {
            // 1. Obtener usuario autenticado
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return AuthResponseDTO.error("Usuario no autenticado");
            }

            String username = authentication.getName();
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // 2. Validar que las contraseñas nuevas coincidan
            if (!changePasswordDTO.isPasswordConfirmationValid()) {
                return AuthResponseDTO.error("Las contraseñas no coinciden");
            }

            // 3. Verificar la contraseña actual
            if (!passwordEncoder.matches(changePasswordDTO.currentPassword(), user.getPassword())) {
                log.warn("Intento de cambio de contraseña con contraseña actual incorrecta para: {}", username);
                return AuthResponseDTO.error("Contraseña actual incorrecta");
            }

            // 4. Validar que la nueva contraseña sea diferente
            if (passwordEncoder.matches(changePasswordDTO.newPassword(), user.getPassword())) {
                return AuthResponseDTO.error("La nueva contraseña debe ser diferente a la actual");
            }

            // 5. Validar longitud mínima
            if (changePasswordDTO.newPassword().length() < 8) {
                return AuthResponseDTO.error("La nueva contraseña debe tener al menos 8 caracteres");
            }

            // 6. Verificar estado de la cuenta
            if (!user.isEnabled()) {
                return AuthResponseDTO.error("Cuenta deshabilitada");
            }

            if (user.isAccountTemporarilyLocked()) {
                return AuthResponseDTO.error("Cuenta bloqueada temporalmente");
            }

            // 7. ✅ MEJORA: Actualizar contraseña y metadata
            user.setPassword(passwordEncoder.encode(changePasswordDTO.newPassword()));
            user.setPasswordChangedAt(LocalDateTime.now());
            user.resetFailedLoginAttempts();

            userRepository.save(user);

            log.info("Contraseña cambiada exitosamente para usuario: {}", user.getEmail());

            // 8. ✅ CAMBIO PRINCIPAL: Revocar TODAS las sesiones existentes por seguridad
            try {
                jwtSessionService.closeAllUserSessions(user.getId());
                log.info("TODAS las sesiones revocadas después de cambio de contraseña para: {}", username);
            } catch (Exception e) {
                log.warn("Error revocando sesiones después de cambio de contraseña: {}", e.getMessage());
                // No lanzamos excepción porque el cambio de contraseña ya fue exitoso
            }

            // 9. Opcional: Notificar por email
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
     * Implementación del servicio de cambio de correo electrónico
     */

    @Override
    @Transactional
    public AuthResponseDTO changeEmail(ChangeEmailDTO changeEmailDTO) {
        log.info("Procesando cambio de email");

        try {
            // 1. Obtener usuario autenticado
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                return AuthResponseDTO.error("Usuario no autenticado");
            }

            String currentEmail = authentication.getName();
            User user = userRepository.findByEmail(currentEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // 2. Normalizar emails
            String newEmail = changeEmailDTO.newEmail().toLowerCase().trim();
            String newEmailConfirmation = changeEmailDTO.newEmailConfirmation().toLowerCase().trim();

            // 3. Validar que los emails coincidan
            if (!newEmail.equals(newEmailConfirmation)) {
                return AuthResponseDTO.error("Los correos electrónicos no coinciden");
            }

            // 4. Validar que el nuevo email sea diferente
            if (newEmail.equals(currentEmail.toLowerCase())) {
                return AuthResponseDTO.error("El nuevo email debe ser diferente al actual");
            }

            // 5. Verificar contraseña actual
            if (!passwordEncoder.matches(changeEmailDTO.currentPassword(), user.getPassword())) {
                log.warn("Intento de cambio de email con contraseña incorrecta para: {}", currentEmail);
                return AuthResponseDTO.error("Contraseña incorrecta");
            }

            // 6. ✅ MEJORA: Verificar que el nuevo email no exista
            if (userRepository.existsByEmail(newEmail)) {
                return AuthResponseDTO.error("El email ya está en uso");
            }

            // 7. ✅ MEJORA: Marcar email como no verificado
            String oldEmail = user.getEmail();
            user.setEmail(newEmail);
            user.setEmailVerified(false); // Requerir nueva verificación

            userRepository.save(user);

            log.info("Email cambiado exitosamente de {} a {} para usuario ID: {}",
                    oldEmail, newEmail, user.getId());

            // 8. Generar código de verificación para el nuevo email
            try {
                String verificationCode = tokenRedisService.generateAndStoreActivationCode(user.getId());
                emailService.sendEmailChangeVerification(user, verificationCode);
                log.info("Código de verificación enviado al nuevo email: {}", newEmail);
            } catch (Exception e) {
                log.error("Error enviando código de verificación al nuevo email: {}", e.getMessage());
            }

            // 9. Notificar al email anterior
            try {
                emailService.sendEmailChangedNotification(oldEmail, newEmail);
            } catch (Exception e) {
                log.warn("Error enviando notificación al email anterior: {}", e.getMessage());
            }

            return AuthResponseDTO.success(
                    "Email cambiado exitosamente. Revisa tu nuevo correo para verificarlo.");

        } catch (UsernameNotFoundException e) {
            log.error("Usuario no encontrado al cambiar email: {}", e.getMessage());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error inesperado al cambiar email: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    /**
     * Implementación del servicio de actualización de información del usuario
     */

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

            // Convertir User a UserInfoDTO
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
    public AuthResponseDTO requestImmediateUnlock(RequestImmediateUnlockDTO requestImmediateUnlockDTO) {
        String normalizedEmail = requestImmediateUnlockDTO.email().toLowerCase().trim();
        try {
            User user = userRepository.findByEmail(normalizedEmail).orElse(null);

            if (user == null) {
                return AuthResponseDTO.success("Si el correo es válido y está bloqueado, recibirás un código");
            }

            // Verificar que esté realmente bloqueado
            if (user.getFailedLoginAttempts() < maxFailedAttempts) {
                return AuthResponseDTO.success("Si el correo es válido y está bloqueado, recibirás un código");
            }

            // Rate limiting
            if (!tokenRedisService.canRequestToken(user.getId(), "unlock")) {
                return AuthResponseDTO.error("Demasiadas solicitudes. Intenta en 1 hora");
            }

            // Generar código y almacenar en Redis
            String unlockCode = tokenRedisService.generateAndStoreUnlockCode(user.getId());

            // Enviar email
            emailService.sendUnlockCode(user, unlockCode);

            log.info("Unlock code sent to user: {}", user.getEmail());
            return AuthResponseDTO.success("Código de desbloqueo enviado a tu email");

        } catch (Exception e) {
            log.error("Error al solicitar desbloqueo inmediato: {}", e.getMessage(), e);
            return AuthResponseDTO.error("Error al enviar el código");
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

            // Usar el JwtSessionService para refrescar
            JwtSessionService.SessionTokens newTokens = jwtSessionService.refreshAccessToken(refreshToken);

            // ✅ ALTERNATIVA: Extraer userId directamente del JWT
            String accessToken = newTokens.getAccessToken();
            String username = jwtUtil.extractUsername(accessToken);

            if (username == null) {
                log.warn("No se pudo extraer username del access token renovado");
                return AuthResponseDTO.error("Error al renovar tokens");
            }

            // Obtener usuario por email (username)
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + username));

            // Validaciones de usuario
            if (!user.isEnabled()) {
                log.warn("Intento de refresh token con usuario inactivo: {}", user.getEmail());
                return AuthResponseDTO.error("Usuario inactivo");
            }

            if (user.isAccountTemporarilyLocked()) {
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

    @Override
    @Transactional
    public AuthResponseDTO verifyUnlockCode(VerifyUnlockCodeDTO verifyUnlockCodeDTO) {
        log.info("Procesando verificación de código de desbloqueo");

        try {
            // Verificar y consumir código - operación atómica
            Long userId = tokenRedisService.verifyAndConsumeUnlockCode(verifyUnlockCodeDTO.code());

            if (userId == null) {
                log.warn("Código de desbloqueo inválido o expirado");
                return AuthResponseDTO.error("Código de desbloqueo incorrecto o expirado");
            }

            // Buscar usuario por ID
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con ID: " + userId));

            // Verificar que la cuenta realmente esté bloqueada
            if (!user.isAccountTemporarilyLocked()) {
                log.info("La cuenta del usuario {} no está bloqueada", user.getEmail());
                return AuthResponseDTO.success("La cuenta ya está desbloqueada");
            }

            // ✅ CORRECCIÓN: Desbloquear cuenta correctamente
            user.resetFailedLoginAttempts(); // Esto ya setea accountLockedUntil = null
            userRepository.save(user);

            log.info("Cuenta desbloqueada exitosamente para usuario: {} - Email: {}", userId, user.getEmail());

            // Email de confirmación (opcional - comentar si no existe el método)
            try {
                emailService.sendAccountUnlockedEmail(user);
            } catch (Exception e) {
                log.warn("Error enviando email de confirmación de desbloqueo: {}", e.getMessage());
                // No fallar la operación si falla el email
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

}