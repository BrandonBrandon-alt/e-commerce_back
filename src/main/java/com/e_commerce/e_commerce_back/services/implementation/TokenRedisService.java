package com.e_commerce.e_commerce_back.services.implementation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import com.e_commerce.e_commerce_back.security.JwtUtil;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Servicio mejorado para manejo de tokens temporales en Redis
 * Implementa operaciones atómicas, rate limiting, y gestión completa de tokens
 */
@Service
@Slf4j
public class TokenRedisService {

    private final RedisTemplate<String, String> redisTemplate;
    private final JwtUtil jwtUtil;

    // Constructor con @Qualifier para especificar el bean correcto
    public TokenRedisService(
            @Qualifier("customStringRedisTemplate") RedisTemplate<String, String> redisTemplate,
            JwtUtil jwtUtil) {
        this.redisTemplate = redisTemplate;
        this.jwtUtil = jwtUtil;
    }

    // Configuraciones desde application.properties
    @Value("${app.email.activation-code-expiry-minutes:15}")
    private Integer activationCodeExpiryMinutes;

    @Value("${app.email.reset-password-code-expiry-minutes:15}")
    private Integer resetPasswordCodeExpiryMinutes;

    @Value("${app.security.unlock-code-expiry-minutes:15}")
    private Integer unlockCodeExpiryMinutes;

    @Value("${app.security.email-verification-expiry-hours:24}")
    private Integer emailVerificationExpiryHours;

    // Rate limiting
    private static final int MAX_REQUESTS_PER_HOUR = 3;
    private static final int CODE_LENGTH = 6;

    // Prefijos de keys para Redis
    private static final String ACTIVATION_PREFIX = "activation_code:";
    private static final String RESET_PREFIX = "reset_code:";
    private static final String UNLOCK_PREFIX = "unlock_code:";
    private static final String VERIFICATION_PREFIX = "verification_token:";
    private static final String BLACKLIST_PREFIX = "blacklist_token:";
    private static final String RATE_LIMIT_SUFFIX = "_rate_limit:";

    // Mappings para búsqueda eficiente
    private static final String ACTIVATION_MAPPING_PREFIX = "activation_mapping:";
    private static final String RESET_MAPPING_PREFIX = "reset_mapping:";
    private static final String UNLOCK_MAPPING_PREFIX = "unlock_mapping:";

    // ================= ACTIVATION CODE (MEJORADO) =================

    /**
     * Genera y almacena código de activación en Redis
     */
    public String generateAndStoreActivationCode(Long userId) {
        String code = generateSecureCode(CODE_LENGTH);
        String key = ACTIVATION_PREFIX + userId;

        // Almacenar en ambas direcciones
        redisTemplate.opsForValue().set(key, code, Duration.ofMinutes(activationCodeExpiryMinutes));
        storeCodeToUserIdMapping(code, userId, "activation");

        log.info("Código de activación generado para usuario: {} -> {}", userId, code);
        return code;
    }

    /**
     * Verifica código de activación (sin consumir)
     */
    public boolean isActivationCodeValid(Long userId, String code) {
        String key = ACTIVATION_PREFIX + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        return storedCode != null && storedCode.equals(code.trim());
    }

    /**
     * Verifica y consume código de activación - VERSIÓN MEJORADA
     */
    public Long verifyAndConsumeActivationCode(String activationCode) {
        log.info("Verificando código de activación: {}", activationCode);

        String mappingKey = getMappingKey("activation", activationCode.trim());
        String userIdStr = redisTemplate.opsForValue().get(mappingKey);

        if (userIdStr != null) {
            try {
                Long userId = Long.parseLong(userIdStr);

                // Verificar que el código coincide en el almacenamiento principal
                String mainKey = ACTIVATION_PREFIX + userId;
                String storedCode = redisTemplate.opsForValue().get(mainKey);

                if (activationCode.trim().equals(storedCode)) {
                    // Eliminar ambas entradas atómicamente
                    redisTemplate.delete(mainKey);
                    redisTemplate.delete(mappingKey);

                    log.info("Código de activación verificado exitosamente para userId: {}", userId);
                    return userId;
                }
            } catch (NumberFormatException e) {
                log.error("Formato de userId inválido: {}", userIdStr);
            }
        }

        log.warn("Código de activación no encontrado: {}", activationCode);
        return null;
    }

    /**
     * Reenvía código de activación con rate limiting
     */
    public String resendActivationCodeWithRateLimit(Long userId) {
        if (!canRequestToken(userId, "activation")) {
            Duration remaining = getRateLimitTimeRemaining(userId, "activation");
            throw new RuntimeException(String.format(
                    "Demasiados intentos. Intente nuevamente en %d minutos",
                    remaining.toMinutes()));
        }

        invalidateActivationCode(userId);
        return generateAndStoreActivationCode(userId);
    }

    // ================= RESET PASSWORD CODE (MEJORADO) =================

    /**
     * Genera y almacena código de reset password - VERSIÓN MEJORADA
     */
    public String generateAndStoreResetCode(Long userId) {
        String code = generateSecureCode(CODE_LENGTH);
        String key = RESET_PREFIX + userId;

        // Almacenar en ambas direcciones
        redisTemplate.opsForValue().set(key, code, Duration.ofMinutes(resetPasswordCodeExpiryMinutes));
        storeCodeToUserIdMapping(code, userId, "reset");

        log.info("Código de reset generado para usuario: {} -> {}", userId, code);
        return code;
    }

    /**
     * Verifica código de reset (sin consumir)
     */
    public boolean isResetCodeValid(Long userId, String code) {
        String key = RESET_PREFIX + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        return storedCode != null && storedCode.equals(code.trim());
    }

    /**
     * Verifica y consume código de reset - VERSIÓN MEJORADA
     */
    public Long verifyAndConsumeResetCode(String resetCode) {
        log.info("Verificando código de reset: {}", resetCode);

        String mappingKey = getMappingKey("reset", resetCode.trim());
        String userIdStr = redisTemplate.opsForValue().get(mappingKey);

        if (userIdStr != null) {
            try {
                Long userId = Long.parseLong(userIdStr);

                // Verificar que el código coincide en el almacenamiento principal
                String mainKey = RESET_PREFIX + userId;
                String storedCode = redisTemplate.opsForValue().get(mainKey);

                if (resetCode.trim().equals(storedCode)) {
                    // Eliminar ambas entradas atómicamente
                    redisTemplate.delete(mainKey);
                    redisTemplate.delete(mappingKey);

                    log.info("Código de reset verificado exitosamente para userId: {}", userId);
                    return userId;
                }
            } catch (NumberFormatException e) {
                log.error("Formato de userId inválido: {}", userIdStr);
            }
        }

        log.warn("Código de reset no encontrado: {}", resetCode);
        return null;
    }

    /**
     * Reenvía código de reset con rate limiting
     */
    public String resendResetCodeWithRateLimit(Long userId) {
        if (!canRequestToken(userId, "reset")) {
            Duration remaining = getRateLimitTimeRemaining(userId, "reset");
            throw new RuntimeException(String.format(
                    "Demasiados intentos. Intente nuevamente en %d minutos",
                    remaining.toMinutes()));
        }

        invalidateResetCode(userId);
        return generateAndStoreResetCode(userId);
    }

    // ================= UNLOCK CODE (MEJORADO) =================

    /**
     * Genera y almacena código de desbloqueo - VERSIÓN MEJORADA
     */
    public String generateAndStoreUnlockCode(Long userId) {
        String code = generateSecureCode(CODE_LENGTH);
        String key = UNLOCK_PREFIX + userId;

        // Almacenar en ambas direcciones
        redisTemplate.opsForValue().set(key, code, Duration.ofMinutes(unlockCodeExpiryMinutes));
        storeCodeToUserIdMapping(code, userId, "unlock");

        log.info("Código de desbloqueo generado para usuario: {} -> {}", userId, code);
        return code;
    }

    /**
     * Verifica código de desbloqueo (sin consumir)
     */
    public boolean isUnlockCodeValid(Long userId, String code) {
        String key = UNLOCK_PREFIX + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        return storedCode != null && storedCode.equals(code.trim());
    }

    /**
     * Verifica y consume código de desbloqueo - VERSIÓN MEJORADA
     */
    public Long verifyAndConsumeUnlockCode(String unlockCode) {
        log.info("Verificando código de desbloqueo: {}", unlockCode);

        String mappingKey = getMappingKey("unlock", unlockCode.trim());
        String userIdStr = redisTemplate.opsForValue().get(mappingKey);

        if (userIdStr != null) {
            try {
                Long userId = Long.parseLong(userIdStr);

                // Verificar que el código coincide en el almacenamiento principal
                String mainKey = UNLOCK_PREFIX + userId;
                String storedCode = redisTemplate.opsForValue().get(mainKey);

                if (unlockCode.trim().equals(storedCode)) {
                    // Eliminar ambas entradas atómicamente
                    redisTemplate.delete(mainKey);
                    redisTemplate.delete(mappingKey);

                    log.info("Código de desbloqueo verificado exitosamente para userId: {}", userId);
                    return userId;
                }
            } catch (NumberFormatException e) {
                log.error("Formato de userId inválido: {}", userIdStr);
            }
        }

        log.warn("Código de desbloqueo no encontrado: {}", unlockCode);
        return null;
    }

    // ================= EMAIL VERIFICATION TOKEN (MEJORADO) =================

    /**
     * Genera y almacena token de verificación de email
     */
    public String generateAndStoreVerificationToken(Long userId) {
        String token = generateSecureToken();
        String key = VERIFICATION_PREFIX + userId;

        redisTemplate.opsForValue().set(
                key,
                token,
                Duration.ofHours(emailVerificationExpiryHours));

        log.info("Token de verificación generado para usuario: {} (TTL: {} horas)",
                userId, emailVerificationExpiryHours);
        return token;
    }

    /**
     * Verifica token de verificación (sin consumir)
     */
    public boolean isVerificationTokenValid(Long userId, String token) {
        String key = VERIFICATION_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().get(key);
        return storedToken != null && storedToken.equals(token.trim());
    }

    /**
     * Verifica y consume token de verificación - VERSIÓN ATÓMICA
     */
    public boolean verifyAndConsumeVerificationToken(Long userId, String token) {
        String key = VERIFICATION_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().getAndDelete(key);

        if (storedToken != null && storedToken.equals(token.trim())) {
            log.info("Token de verificación consumido para usuario: {}", userId);
            return true;
        }

        log.warn("Token de verificación inválido para usuario: {}", userId);
        return false;
    }

    /**
     * Revoca token de verificación
     */
    public void revokeVerificationToken(Long userId) {
        String key = VERIFICATION_PREFIX + userId;
        redisTemplate.delete(key);
        log.info("Token de verificación revocado para usuario: {}", userId);
    }

    // ================= ACCESS TOKEN BLACKLIST (MEJORADO) =================

    /**
     * Agrega access token a blacklist
     */
    public void blacklistAccessToken(String token) {
        try {
            java.util.Date expiration = jwtUtil.extractExpiration(token);
            Duration ttl = Duration.between(Instant.now(), expiration.toInstant());

            if (ttl.isPositive()) {
                String key = BLACKLIST_PREFIX + token;
                redisTemplate.opsForValue().set(key, "revoked", ttl);
                log.info("Access token agregado a blacklist (TTL: {} minutos)", ttl.toMinutes());
            } else {
                log.warn("Token ya expirado, no se agrega a blacklist");
            }
        } catch (Exception e) {
            log.error("Error al agregar token a blacklist: {}", e.getMessage());
        }
    }

    /**
     * Verifica si un access token está en blacklist
     */
    public boolean isTokenBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    // ================= RATE LIMITING (MEJORADO) =================

    /**
     * Verifica si se puede solicitar un nuevo token
     */
    public boolean canRequestToken(Long userId, String tokenType) {
        String key = tokenType + RATE_LIMIT_SUFFIX + userId;
        String count = redisTemplate.opsForValue().get(key);

        if (count == null) {
            redisTemplate.opsForValue().set(key, "1", Duration.ofHours(1));
            log.debug("Primera solicitud de token tipo '{}' para usuario: {}", tokenType, userId);
            return true;
        }

        int currentCount = Integer.parseInt(count);
        if (currentCount >= MAX_REQUESTS_PER_HOUR) {
            log.warn("Rate limit excedido para usuario {} y tipo '{}'", userId, tokenType);
            return false;
        }

        redisTemplate.opsForValue().increment(key);
        log.debug("Solicitud de token tipo '{}' para usuario: {} (count: {})",
                tokenType, userId, currentCount + 1);
        return true;
    }

    /**
     * Obtiene el número de intentos restantes
     */
    public int getRemainingAttempts(Long userId, String tokenType) {
        String key = tokenType + RATE_LIMIT_SUFFIX + userId;
        String count = redisTemplate.opsForValue().get(key);

        if (count == null) {
            return MAX_REQUESTS_PER_HOUR;
        }

        int currentCount = Integer.parseInt(count);
        return Math.max(0, MAX_REQUESTS_PER_HOUR - currentCount);
    }

    /**
     * Obtiene tiempo restante del rate limit
     */
    public Duration getRateLimitTimeRemaining(Long userId, String tokenType) {
        String key = tokenType + RATE_LIMIT_SUFFIX + userId;
        Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);

        if (ttl != null && ttl > 0) {
            return Duration.ofSeconds(ttl);
        }
        return Duration.ZERO;
    }

    /**
     * Limpia rate limit (uso administrativo)
     */
    public void clearRateLimit(Long userId, String tokenType) {
        String key = tokenType + RATE_LIMIT_SUFFIX + userId;
        redisTemplate.delete(key);
        log.info("Rate limit limpiado para usuario {} y tipo '{}'", userId, tokenType);
    }

    /**
     * Limpia todos los rate limits de un usuario
     */
    public void clearAllRateLimits(Long userId) {
        String[] tokenTypes = { "activation", "reset", "unlock" };
        for (String type : tokenTypes) {
            clearRateLimit(userId, type);
        }
        log.info("Todos los rate limits limpiados para usuario: {}", userId);
    }

    // ================= MÉTODOS DE UTILIDAD =================

    /**
     * Verifica si existe un código activo
     */
    public boolean hasActiveActivationCode(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(ACTIVATION_PREFIX + userId));
    }

    public boolean hasActiveResetCode(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(RESET_PREFIX + userId));
    }

    public boolean hasActiveUnlockCode(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(UNLOCK_PREFIX + userId));
    }

    public boolean hasActiveVerificationToken(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(VERIFICATION_PREFIX + userId));
    }

    /**
     * Obtiene TTL en minutos
     */
    public long getActivationCodeTTL(Long userId) {
        Long ttl = redisTemplate.getExpire(ACTIVATION_PREFIX + userId, TimeUnit.MINUTES);
        return ttl != null ? ttl : -1;
    }

    public long getResetCodeTTL(Long userId) {
        Long ttl = redisTemplate.getExpire(RESET_PREFIX + userId, TimeUnit.MINUTES);
        return ttl != null ? ttl : -1;
    }

    public long getUnlockCodeTTL(Long userId) {
        Long ttl = redisTemplate.getExpire(UNLOCK_PREFIX + userId, TimeUnit.MINUTES);
        return ttl != null ? ttl : -1;
    }

    public long getVerificationTokenTTL(Long userId) {
        Long ttl = redisTemplate.getExpire(VERIFICATION_PREFIX + userId, TimeUnit.HOURS);
        return ttl != null ? ttl : -1;
    }

    /**
     * Invalida códigos manualmente
     */
    public void invalidateActivationCode(Long userId) {
        String mainKey = ACTIVATION_PREFIX + userId;
        String code = redisTemplate.opsForValue().get(mainKey);

        if (code != null) {
            String mappingKey = getMappingKey("activation", code);
            redisTemplate.delete(mappingKey);
        }
        redisTemplate.delete(mainKey);

        log.info("Código de activación invalidado manualmente para usuario: {}", userId);
    }

    public void invalidateResetCode(Long userId) {
        String mainKey = RESET_PREFIX + userId;
        String code = redisTemplate.opsForValue().get(mainKey);

        if (code != null) {
            String mappingKey = getMappingKey("reset", code);
            redisTemplate.delete(mappingKey);
        }
        redisTemplate.delete(mainKey);

        log.info("Código de reset invalidado manualmente para usuario: {}", userId);
    }

    public void invalidateUnlockCode(Long userId) {
        String mainKey = UNLOCK_PREFIX + userId;
        String code = redisTemplate.opsForValue().get(mainKey);

        if (code != null) {
            String mappingKey = getMappingKey("unlock", code);
            redisTemplate.delete(mappingKey);
        }
        redisTemplate.delete(mainKey);

        log.info("Código de desbloqueo invalidado manualmente para usuario: {}", userId);
    }

    /**
     * Invalida todos los tokens de un usuario
     */
    public void invalidateAllUserTokens(Long userId) {
        invalidateActivationCode(userId);
        invalidateResetCode(userId);
        invalidateUnlockCode(userId);
        revokeVerificationToken(userId);
        clearAllRateLimits(userId);

        log.warn("TODOS los tokens invalidados para usuario: {}", userId);
    }

    /**
     * Obtiene estado completo de tokens de un usuario
     */
    public TokensStatusDTO getUserTokensStatus(Long userId) {
        return TokensStatusDTO.builder()
                .userId(userId)
                .hasActivationCode(hasActiveActivationCode(userId))
                .hasResetCode(hasActiveResetCode(userId))
                .hasUnlockCode(hasActiveUnlockCode(userId))
                .hasVerificationToken(hasActiveVerificationToken(userId))
                .activationCodeTTL(getActivationCodeTTL(userId))
                .resetCodeTTL(getResetCodeTTL(userId))
                .unlockCodeTTL(getUnlockCodeTTL(userId))
                .verificationTokenTTL(getVerificationTokenTTL(userId))
                .activationRemainingAttempts(getRemainingAttempts(userId, "activation"))
                .resetRemainingAttempts(getRemainingAttempts(userId, "reset"))
                .unlockRemainingAttempts(getRemainingAttempts(userId, "unlock"))
                .build();
    }

    // ================= MÉTODOS PRIVADOS DE UTILIDAD =================

    /**
     * Genera código numérico seguro
     */
    private String generateSecureCode(int length) {
        Random random = new Random();
        return String.format("%0" + length + "d", random.nextInt((int) Math.pow(10, length)));
    }

    /**
     * Genera token alfanumérico seguro
     */
    private String generateSecureToken() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Almacena mapeo código→userId
     */
    private void storeCodeToUserIdMapping(String code, Long userId, String type) {
        String mappingKey = getMappingKey(type, code);
        int expiryMinutes = getExpiryMinutesForType(type);

        redisTemplate.opsForValue().set(
                mappingKey,
                userId.toString(),
                Duration.ofMinutes(expiryMinutes));
    }

    /**
     * Obtiene key de mapeo
     */
    private String getMappingKey(String type, String code) {
        return type + "_mapping:" + code;
    }

    /**
     * Obtiene minutos de expiración según el tipo
     */
    private int getExpiryMinutesForType(String type) {
        switch (type) {
            case "activation":
                return activationCodeExpiryMinutes;
            case "reset":
                return resetPasswordCodeExpiryMinutes;
            case "unlock":
                return unlockCodeExpiryMinutes;
            default:
                return 15;
        }
    }

    // ================= DTO =================

    @lombok.Builder
    @lombok.Data
    public static class TokensStatusDTO {
        private Long userId;
        private boolean hasActivationCode;
        private boolean hasResetCode;
        private boolean hasUnlockCode;
        private boolean hasVerificationToken;
        private long activationCodeTTL;
        private long resetCodeTTL;
        private long unlockCodeTTL;
        private long verificationTokenTTL;
        private int activationRemainingAttempts;
        private int resetRemainingAttempts;
        private int unlockRemainingAttempts;
    }
}