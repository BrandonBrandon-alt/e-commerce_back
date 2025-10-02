package com.e_commerce.e_commerce_back.services.implementation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@RequiredArgsConstructor
@Slf4j
public class TokenRedisService {

    private final RedisTemplate<String, String> redisTemplate;
    private final JwtUtil jwtUtil;

    // Configuraciones desde application.properties
    @Value("${app.email.activation-code-expiry-minutes:15}")
    private Integer activationCodeExpiryMinutes;

    @Value("${app.email.reset-password-code-expiry-minutes:15}")
    private Integer resetPasswordCodeExpiryMinutes;

    @Value("${app.security.unlock-code-expiry-minutes:15}")
    private Integer unlockCodeExpiryMinutes;

    @Value("${app.security.refresh-token-expiry-days:7}")
    private Integer refreshTokenExpiryDays;

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
    private static final String REFRESH_PREFIX = "refresh_token:";
    private static final String BLACKLIST_PREFIX = "blacklist_token:";
    private static final String RATE_LIMIT_SUFFIX = "_rate_limit:";

    // ================= ACTIVATION CODE (MEJORADO) =================

    /**
     * Genera y almacena código de activación en Redis
     */
    public String generateAndStoreActivationCode(Long userId) {
        String code = generateSecureCode(CODE_LENGTH);
        String key = ACTIVATION_PREFIX + userId;

        redisTemplate.opsForValue().set(
                key,
                code,
                Duration.ofMinutes(activationCodeExpiryMinutes));

        log.info("Código de activación generado y almacenado para usuario: {} (TTL: {} minutos)", 
                userId, activationCodeExpiryMinutes);
        return code;
    }

    /**
     * Verifica código de activación (sin consumir)
     * Útil para validaciones previas
     */
    public boolean isActivationCodeValid(Long userId, String code) {
        String key = ACTIVATION_PREFIX + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        return storedCode != null && storedCode.equals(code.trim());
    }

    /**
     * Obtiene el userId asociado a un código de activación (sin consumir)
     */
    public Long getUserIdByActivationCode(String activationCode) {
        return findUserIdByCode(ACTIVATION_PREFIX + "*", activationCode, "activation");
    }

    /**
     * Verifica y consume código de activación usando solo el código
     * VERSIÓN ATÓMICA - Evita condiciones de carrera
     */
    public Long verifyAndConsumeActivationCode(String activationCode) {
        log.info("Verificando y consumiendo código de activación");
        
        try {
            String pattern = ACTIVATION_PREFIX + "*";
            Set<String> keys = redisTemplate.keys(pattern);
            
            if (keys == null || keys.isEmpty()) {
                log.warn("No hay códigos de activación en Redis");
                return null;
            }

            for (String key : keys) {
                // Operación atómica: obtener y eliminar en un solo paso
                String storedCode = redisTemplate.opsForValue().getAndDelete(key);
                
                if (storedCode != null && storedCode.equals(activationCode.trim())) {
                    Long userId = extractUserIdFromKey(key, ACTIVATION_PREFIX);
                    if (userId != null) {
                        log.info("Código de activación verificado y consumido atómicamente para userId: {}", userId);
                        return userId;
                    }
                }
            }
            
            log.warn("Código de activación no encontrado o inválido");
            return null;
            
        } catch (Exception e) {
            log.error("Error al verificar código de activación: {}", e.getMessage(), e);
            return null;
        }
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
     * Genera y almacena código de reset password
     */
    public String generateAndStoreResetCode(Long userId) {
        String code = generateSecureCode(CODE_LENGTH);
        String key = RESET_PREFIX + userId;

        redisTemplate.opsForValue().set(
                key,
                code,
                Duration.ofMinutes(resetPasswordCodeExpiryMinutes));

        log.info("Código de reset generado para usuario: {} (TTL: {} minutos)", 
                userId, resetPasswordCodeExpiryMinutes);
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
     * Obtiene userId por código de reset
     */
    public Long getUserIdByResetCode(String resetCode) {
        return findUserIdByCode(RESET_PREFIX + "*", resetCode, "reset");
    }

    /**
     * Verifica y consume código de reset - VERSIÓN ATÓMICA
     */
    public Long verifyAndConsumeResetCode(String resetCode) {
        log.info("Verificando y consumiendo código de reset");
        
        try {
            String pattern = RESET_PREFIX + "*";
            Set<String> keys = redisTemplate.keys(pattern);
            
            if (keys == null || keys.isEmpty()) {
                log.warn("No hay códigos de reset en Redis");
                return null;
            }

            for (String key : keys) {
                String storedCode = redisTemplate.opsForValue().getAndDelete(key);
                
                if (storedCode != null && storedCode.equals(resetCode.trim())) {
                    Long userId = extractUserIdFromKey(key, RESET_PREFIX);
                    if (userId != null) {
                        log.info("Código de reset verificado y consumido para userId: {}", userId);
                        return userId;
                    }
                }
            }
            
            log.warn("Código de reset no encontrado o inválido");
            return null;
            
        } catch (Exception e) {
            log.error("Error al verificar código de reset: {}", e.getMessage(), e);
            return null;
        }
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
     * Genera y almacena código de desbloqueo
     */
    public String generateAndStoreUnlockCode(Long userId) {
        String code = generateSecureCode(CODE_LENGTH);
        String key = UNLOCK_PREFIX + userId;

        redisTemplate.opsForValue().set(
                key,
                code,
                Duration.ofMinutes(unlockCodeExpiryMinutes));

        log.info("Código de desbloqueo generado para usuario: {} (TTL: {} minutos)", 
                userId, unlockCodeExpiryMinutes);
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
     * Obtiene userId por código de desbloqueo
     */
    public Long getUserIdByUnlockCode(String unlockCode) {
        return findUserIdByCode(UNLOCK_PREFIX + "*", unlockCode, "unlock");
    }

    /**
     * Verifica y consume código de desbloqueo - VERSIÓN ATÓMICA
     */
    public Long verifyAndConsumeUnlockCode(String unlockCode) {
        log.info("Verificando y consumiendo código de desbloqueo");
        
        try {
            String pattern = UNLOCK_PREFIX + "*";
            Set<String> keys = redisTemplate.keys(pattern);
            
            if (keys == null || keys.isEmpty()) {
                log.warn("No hay códigos de desbloqueo en Redis");
                return null;
            }

            for (String key : keys) {
                String storedCode = redisTemplate.opsForValue().getAndDelete(key);
                
                if (storedCode != null && storedCode.equals(unlockCode.trim())) {
                    Long userId = extractUserIdFromKey(key, UNLOCK_PREFIX);
                    if (userId != null) {
                        log.info("Código de desbloqueo verificado y consumido para userId: {}", userId);
                        return userId;
                    }
                }
            }
            
            log.warn("Código de desbloqueo no encontrado o inválido");
            return null;
            
        } catch (Exception e) {
            log.error("Error al verificar código de desbloqueo: {}", e.getMessage(), e);
            return null;
        }
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

    // ================= REFRESH TOKEN (MEJORADO) =================

    /**
     * Genera y almacena refresh token
     */
    public String generateAndStoreRefreshToken(Long userId) {
        String token = generateSecureToken();
        String key = REFRESH_PREFIX + userId;

        redisTemplate.opsForValue().set(
                key,
                token,
                Duration.ofDays(refreshTokenExpiryDays));

        log.info("Refresh token generado para usuario: {} (TTL: {} días)", 
                userId, refreshTokenExpiryDays);
        return token;
    }

    /**
     * Verifica refresh token (sin consumir)
     */
    public boolean isRefreshTokenValid(Long userId, String token) {
        String key = REFRESH_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().get(key);
        return storedToken != null && storedToken.equals(token.trim());
    }

    /**
     * Verifica y renueva refresh token
     */
    public String verifyAndRenewRefreshToken(Long userId, String token) {
        String key = REFRESH_PREFIX + userId;
        String storedToken = redisTemplate.opsForValue().get(key);

        if (storedToken == null || !storedToken.equals(token.trim())) {
            log.warn("Refresh token inválido para usuario: {}", userId);
            return null;
        }

        // Generar nuevo token
        String newToken = generateSecureToken();
        redisTemplate.opsForValue().set(
                key, 
                newToken, 
                Duration.ofDays(refreshTokenExpiryDays));

        log.info("Refresh token renovado para usuario: {}", userId);
        return newToken;
    }

    /**
     * Revoca refresh token
     */
    public void revokeRefreshToken(Long userId) {
        String key = REFRESH_PREFIX + userId;
        Boolean deleted = redisTemplate.delete(key);
        if (Boolean.TRUE.equals(deleted)) {
            log.info("Refresh token revocado para usuario: {}", userId);
        }
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

    /**
     * Limpia tokens expirados de la blacklist (mantenimiento)
     */
    public long cleanupBlacklistedTokens() {
        String pattern = BLACKLIST_PREFIX + "*";
        Set<String> keys = redisTemplate.keys(pattern);
        
        if (keys == null || keys.isEmpty()) {
            return 0;
        }

        long cleaned = 0;
        for (String key : keys) {
            Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
            if (ttl != null && ttl <= 0) {
                redisTemplate.delete(key);
                cleaned++;
            }
        }

        log.info("Limpieza de blacklist completada. Tokens eliminados: {}", cleaned);
        return cleaned;
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
        String[] tokenTypes = {"activation", "reset", "unlock"};
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

    public boolean hasActiveRefreshToken(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(REFRESH_PREFIX + userId));
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

    public long getRefreshTokenTTL(Long userId) {
        Long ttl = redisTemplate.getExpire(REFRESH_PREFIX + userId, TimeUnit.DAYS);
        return ttl != null ? ttl : -1;
    }

    /**
     * Invalida códigos manualmente
     */
    public void invalidateActivationCode(Long userId) {
        redisTemplate.delete(ACTIVATION_PREFIX + userId);
        log.info("Código de activación invalidado manualmente para usuario: {}", userId);
    }

    public void invalidateResetCode(Long userId) {
        redisTemplate.delete(RESET_PREFIX + userId);
        log.info("Código de reset invalidado manualmente para usuario: {}", userId);
    }

    public void invalidateUnlockCode(Long userId) {
        redisTemplate.delete(UNLOCK_PREFIX + userId);
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
        revokeRefreshToken(userId);
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
                .hasRefreshToken(hasActiveRefreshToken(userId))
                .activationCodeTTL(getActivationCodeTTL(userId))
                .resetCodeTTL(getResetCodeTTL(userId))
                .unlockCodeTTL(getUnlockCodeTTL(userId))
                .verificationTokenTTL(getVerificationTokenTTL(userId))
                .refreshTokenTTL(getRefreshTokenTTL(userId))
                .activationRemainingAttempts(getRemainingAttempts(userId, "activation"))
                .resetRemainingAttempts(getRemainingAttempts(userId, "reset"))
                .unlockRemainingAttempts(getRemainingAttempts(userId, "unlock"))
                .build();
    }

    /**
     * Exporta todos los tokens de un usuario (para debug)
     */
    public Map<String, Object> exportUserTokens(Long userId) {
        Map<String, Object> tokens = new HashMap<>();
        
        tokens.put("activation_code", redisTemplate.opsForValue().get(ACTIVATION_PREFIX + userId));
        tokens.put("reset_code", redisTemplate.opsForValue().get(RESET_PREFIX + userId));
        tokens.put("unlock_code", redisTemplate.opsForValue().get(UNLOCK_PREFIX + userId));
        tokens.put("verification_token", redisTemplate.opsForValue().get(VERIFICATION_PREFIX + userId));
        tokens.put("refresh_token", redisTemplate.opsForValue().get(REFRESH_PREFIX + userId));
        tokens.put("status", getUserTokensStatus(userId));
        
        return tokens;
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
     * Busca userId por código (método genérico)
     */
    private Long findUserIdByCode(String pattern, String code, String tokenType) {
        Set<String> keys = redisTemplate.keys(pattern);
        
        if (keys == null || keys.isEmpty()) {
            log.warn("No hay códigos de tipo '{}' en Redis", tokenType);
            return null;
        }

        for (String key : keys) {
            String storedCode = redisTemplate.opsForValue().get(key);
            if (storedCode != null && storedCode.equals(code.trim())) {
                String prefix = pattern.replace("*", "");
                Long userId = extractUserIdFromKey(key, prefix);
                if (userId != null) {
                    log.info("UserId {} encontrado para código de tipo '{}'", userId, tokenType);
                    return userId;
                }
            }
        }
        
        log.warn("No se encontró código de tipo '{}' coincidente", tokenType);
        return null;
    }

    /**
     * Extrae userId de una key de Redis
     */
    private Long extractUserIdFromKey(String key, String prefix) {
        try {
            String userIdStr = key.substring(prefix.length());
            return Long.parseLong(userIdStr);
        } catch (Exception e) {
            log.error("Error al extraer userId de key: {}", key);
            return null;
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
        private boolean hasRefreshToken;
        private long activationCodeTTL;
        private long resetCodeTTL;
        private long unlockCodeTTL;
        private long verificationTokenTTL;
        private long refreshTokenTTL;
        private int activationRemainingAttempts;
        private int resetRemainingAttempts;
        private int unlockRemainingAttempts;
    }
}