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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
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
    
    @Value("${app.security.lockout-duration-minutes:30}")
    private Integer lockoutDurationMinutes;
    
    @Value("${app.email.activation-code-expiry-minutes:15}")
    private Integer activationCodeExpiryMinutes;

    @Override
    public AuthResponseDTO login(LoginDTO loginDTO) {
        log.info("Procesando login para email: {}", loginDTO.email());

        try {
            // Buscar usuario primero para verificar bloqueos
            User user = userRepository.findByEmail(loginDTO.email())
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
                                loginDTO.email(),
                                loginDTO.password()));

                // Login exitoso - resetear intentos fallidos
                user.resetFailedLoginAttempts();
                
                // Actualizar información de último login con contexto de request
                updateLastLoginInfo(user);

                // Guardar cambios del usuario
                userRepository.save(user);

                // Obtener detalles del usuario autenticado
                UserDetails userDetails = (UserDetails) authentication.getPrincipal();

                // Generar token JWT con claims adicionales
                Map<String, Object> extraClaims = buildTokenClaims(user);
                String token = jwtUtil.generateToken(userDetails, extraClaims);

                // Crear información del usuario usando el método factory
                UserInfoDTO userInfo = UserInfoDTO.fromUser(user);

                log.info("Login exitoso para usuario: {} - IP: {} - Intentos previos: {}", 
                         user.getEmail(), 
                         user.getLastIpAddress(),
                         0); // Ya se resetearon

                return AuthResponseDTO.success(token, jwtExpiration, userInfo);

            } catch (BadCredentialsException e) {
                // Incrementar intentos fallidos
                user.incrementFailedLoginAttempts();
                
                // Bloquear cuenta si se superan los intentos máximos
                if (user.getFailedLoginAttempts() >= maxFailedAttempts) {
                    user.lockAccount(lockoutDurationMinutes);
                    userRepository.save(user);
                    log.warn("Cuenta bloqueada por {} intentos fallidos: {}", 
                             maxFailedAttempts, loginDTO.email());
                    throw new BadCredentialsException(
                        String.format("Cuenta bloqueada por %d minutos debido a múltiples intentos fallidos", 
                                     lockoutDurationMinutes));
                }
                
                userRepository.save(user);
                int remainingAttempts = maxFailedAttempts - user.getFailedLoginAttempts();
                
                log.warn("Credenciales inválidas para email: {} - Intentos restantes: {}", 
                         loginDTO.email(), remainingAttempts);
                
                throw new BadCredentialsException(
                    String.format("Email o contraseña incorrectos. Intentos restantes: %d", 
                                 remainingAttempts));
            }

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de login con email no registrado: {}", loginDTO.email());
            throw new BadCredentialsException("Email o contraseña incorrectos");
        } catch (BadCredentialsException e) {
            throw e; // Re-lanzar excepciones de credenciales
        } catch (Exception e) {
            log.error("Error en login para email: {}, error: {}", loginDTO.email(), e.getMessage());
            throw new RuntimeException("Error interno del servidor");
        }
    }

    @Override
    public AuthResponseDTO register(RegisterUserDTO createUserDTO) {
        log.info("Procesando registro para email: {}", createUserDTO.email());

        try {
            // Verificar si el email ya existe
            if (userRepository.existsByEmail(createUserDTO.email())) {
                throw new EmailIsExists("El email ya está registrado");
            }

            // Verificar si el número de identificación ya existe
            if (userRepository.findByIdNumber(createUserDTO.idNumber()).isPresent()) {
                throw new IdNumberIsExists("El número de identificación ya está registrado");
            }

            // Generar código de activación
            String activationCode = emailService.generateActivationCode();
            LocalDateTime codeExpiry = LocalDateTime.now().plusMinutes(activationCodeExpiryMinutes);

            // Usar el builder mejorado de User
            User newUser = User.builder()
                    .idNumber(createUserDTO.idNumber())
                    .name(createUserDTO.name())
                    .lastName(createUserDTO.lastName())
                    .email(createUserDTO.email().toLowerCase().trim()) // Normalizar email
                    .phoneNumber(createUserDTO.phoneNumber())
                    .password(passwordEncoder.encode(createUserDTO.password()))
                    .dateOfBirth(createUserDTO.dateOfBirth()) // Si está disponible en el DTO
                    .role(EnumRole.USER)
                    .status(EnumStatus.INACTIVE) // Requiere activación por email
                    .emailVerified(false)
                    .phoneVerified(false)
                    .failedLoginAttempts(0)
                    .codeActivation(activationCode)
                    .codeActivationExpiry(codeExpiry)
                    .build();

            // El @PrePersist se encargará de los valores por defecto

            // Guardar usuario
            User savedUser = userRepository.save(newUser);

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
            log.error("Error en registro para email: {}, error: {}", createUserDTO.email(), e.getMessage());
            throw new RuntimeException("Error interno del servidor durante el registro");
        }
    }

    @Override
    public TokenValidationDTO validateToken(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (token == null) {
                return TokenValidationDTO.invalid("Token no proporcionado");
            }

            if (jwtUtil.isTokenValid(token)) {
                String username = jwtUtil.extractUsername(token);
                Long remainingTime = jwtUtil.getTokenRemainingTime(token);

                // Verificar que el usuario aún esté habilitado
                User user = userRepository.findByEmail(username).orElse(null);
                if (user == null || !user.isEnabled() || user.isAccountTemporarilyLocked()) {
                    return TokenValidationDTO.invalid("Usuario no válido");
                }

                return TokenValidationDTO.valid(username, remainingTime);
            } else {
                return TokenValidationDTO.invalid("Token inválido o expirado");
            }

        } catch (Exception e) {
            log.error("Error validando token: {}", e.getMessage());
            return TokenValidationDTO.invalid("Error validando token: " + e.getMessage());
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

        // Usar el método factory para consistencia
        return UserInfoDTO.fromUser(user);
    }

    @Override
    public void logout(String authHeader) {
        try {
            String token = extractTokenFromHeader(authHeader);

            if (token != null) {
                // En una implementación más avanzada, aquí se podría:
                // 1. Agregar el token a una blacklist en Redis
                // 2. Almacenar tokens invalidados con TTL
                // 3. Usar un mecanismo de revocación de tokens

                try {
                    // Intentar extraer username del token
                    String username = jwtUtil.extractUsername(token);
                    log.info("Logout procesado para usuario: {}", username);
                } catch (Exception tokenException) {
                    // Si el token es inválido, solo logeamos el intento de logout
                    log.warn("Intento de logout con token inválido: {}", tokenException.getMessage());
                }

                // Limpiar contexto de seguridad independientemente de si el token es válido
                SecurityContextHolder.clearContext();
            } else {
                log.info("Logout procesado sin token válido");
            }

        } catch (Exception e) {
            log.error("Error en logout: {}", e.getMessage());
            // No lanzar excepción para logout - es mejor ser permisivo
            log.warn("Logout completado a pesar del error");
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
     * Construye los claims adicionales para el JWT
     */
    private Map<String, Object> buildTokenClaims(User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId());
        extraClaims.put("role", user.getRole().name());
        extraClaims.put("name", user.getFullName());
        extraClaims.put("emailVerified", user.getEmailVerified());
        extraClaims.put("status", user.getStatus().name());
        
        // Claims útiles para el frontend
        if (user.getAge() != null) {
            extraClaims.put("isMinor", user.isMinor());
        }
        
        return extraClaims;
    }

    /**
     * Actualiza la información del último login con contexto HTTP
     */
    private void updateLastLoginInfo(User user) {
        try {
            ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
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
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
        
        user.resetFailedLoginAttempts();
        userRepository.save(user);
        
        log.info("Cuenta desbloqueada manualmente para usuario: {}", email);
    }

    @Override
    public AuthResponseDTO activateAccount(ActivateAccountDTO activateAccountDTO) {
        log.info("Procesando activación de cuenta para email: {}", activateAccountDTO.email());

        try {
            // Buscar usuario por email
            User user = userRepository.findByEmail(activateAccountDTO.email())
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Verificar si la cuenta ya está activada
            if (user.isEnabled()) {
                return AuthResponseDTO.error("La cuenta ya está activada");
            }

            // Verificar si el código de activación es correcto
            if (!activateAccountDTO.activationCode().equals(user.getCodeActivation())) {
                log.warn("Código de activación incorrecto para usuario: {}", activateAccountDTO.email());
                return AuthResponseDTO.error("Código de activación incorrecto");
            }

            // Verificar si el código no ha expirado
            if (user.isActivationCodeExpired()) {
                log.warn("Código de activación expirado para usuario: {}", activateAccountDTO.email());
                return AuthResponseDTO.error("El código de activación ha expirado. Solicita un nuevo código.");
            }

            // Activar la cuenta
            user.markEmailAsVerified();
            user.clearActivationCode();
            
            // Guardar cambios
            userRepository.save(user);

            log.info("Cuenta activada exitosamente para usuario: {}", activateAccountDTO.email());

            // Enviar email de bienvenida
            try {
                emailService.sendWelcomeEmail(user);
                log.info("Email de bienvenida enviado a: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Error enviando email de bienvenida a {}: {}", 
                         user.getEmail(), e.getMessage());
                // No fallar la activación si el email falla
            }

            return AuthResponseDTO.success("¡Cuenta activada exitosamente! Ya puedes iniciar sesión.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de activación con email no registrado: {}", activateAccountDTO.email());
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error en activación para email: {}, error: {}", activateAccountDTO.email(), e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    @Override
    public AuthResponseDTO resendActivationCode(String email) {
        log.info("Procesando reenvío de código de activación para email: {}", email);

        try {
            // Buscar usuario por email
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

            // Verificar si la cuenta ya está activada
            if (user.isEnabled()) {
                return AuthResponseDTO.error("La cuenta ya está activada");
            }

            // Generar nuevo código de activación
            String newActivationCode = emailService.generateActivationCode();
            LocalDateTime newCodeExpiry = LocalDateTime.now().plusMinutes(activationCodeExpiryMinutes);

            // Actualizar código en el usuario
            user.setCodeActivation(newActivationCode);
            user.setCodeActivationExpiry(newCodeExpiry);

            // Guardar cambios
            userRepository.save(user);

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
            log.warn("Intento de reenvío con email no registrado: {}", email);
            return AuthResponseDTO.error("Usuario no encontrado");
        } catch (Exception e) {
            log.error("Error en reenvío para email: {}, error: {}", email, e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor");
        }
    }

    @Override
    public AuthResponseDTO forgotPassword(ForgotPasswordDTO forgotPasswordDTO) {
        try {
            User user = userRepository.findByEmail(forgotPasswordDTO.email())
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con el email: " + forgotPasswordDTO.email()));

            String resetCode = emailService.generateResetCode();
            user.setCodeResetPassword(resetCode);
            user.setCodeResetPasswordExpiry(LocalDateTime.now().plusMinutes(15)); // El código expira en 15 minutos

            userRepository.save(user);

                        emailService.sendPasswordResetEmail(user, resetCode);

            log.info("Código de reseteo de contraseña enviado a: {}", forgotPasswordDTO.email());
            return AuthResponseDTO.success("Se ha enviado un código de reseteo a tu correo electrónico.");

        } catch (UsernameNotFoundException e) {
            log.warn("Intento de reseteo de contraseña para email no registrado: {}", forgotPasswordDTO.email());
            // Por seguridad, no revelamos si el email existe o no.
            return AuthResponseDTO.success("Si tu correo está registrado, recibirás un código de reseteo.");
        } catch (Exception e) {
            log.error("Error al procesar la solicitud de olvido de contraseña para {}: {}", forgotPasswordDTO.email(), e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor al intentar resetear la contraseña.");
        }
    }

    @Override
    public AuthResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO) {
        try {
            User user = userRepository.findByEmail(resetPasswordDTO.email())
                    .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

             // Verificar si el código de activación es correcto
             if (!resetPasswordDTO.resetCode().equals(user.getCodeResetPassword())) {
                log.warn("Código de activación incorrecto para usuario: {}", resetPasswordDTO.email());
                return AuthResponseDTO.error("Código de activación incorrecto");
            }
            
            if (!resetPasswordDTO.passwordsMatch()) {
                return AuthResponseDTO.error("Las contraseñas no coinciden");
            }
            
            user.setPassword(passwordEncoder.encode(resetPasswordDTO.password()));
            user.clearResetPasswordCode();
            
            userRepository.save(user);
            
            return AuthResponseDTO.success("Contraseña restablecida exitosamente");
            
        } catch (Exception e) {
            log.error("Error al restablecer contraseña para email: {}, error: {}", 
                     resetPasswordDTO.email(), e.getMessage());
            return AuthResponseDTO.error("Error interno del servidor");
        }
   
        
    }

    @Override
    public AuthResponseDTO refreshToken(RefreshTokenDTO refreshTokenDTO) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'refreshToken'");
    }

    @Override
    public void changePassword(ChangePasswordDTO changePasswordDTO) {

       
    }

    @Override
    public void changeEmail(ChangeEmailDTO changeEmailDTO) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'changeEmail'");
    }
}