package com.e_commerce.e_commerce_back.services.implementation;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Servicio para manejo de tokens temporales en Redis
 * Reemplaza las columnas de códigos en la base de datos
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TokenRedisService {

    private final RedisTemplate<String, String> redisTemplate;

    // Usar las mismas configuraciones que ya tienes en AuthServiceImpl
    @Value("${app.email.activation-code-expiry-minutes:15}")
    private Integer activationCodeExpiryMinutes;

    @Value("${app.email.reset-password-code-expiry-minutes:15}")
    private Integer resetPasswordCodeExpiryMinutes;

    @Value("${app.security.unlock-code-expiry-minutes:15}")
    private Integer unlockCodeExpiryMinutes;

    // Rate limiting - máximo 3 solicitudes por hora por tipo
    private static final int MAX_REQUESTS_PER_HOUR = 3;

    // ================= ACTIVATION CODE =================

    /**
     * Genera y almacena código de activación en Redis
     * Reemplaza: user.setCodeActivation() y user.setCodeActivationExpiry()
     */
    public String generateAndStoreActivationCode(Long userId) {
        String code = generateSixDigitCode();
        String key = "activation_code:" + userId;
        
        redisTemplate.opsForValue().set(
            key, 
            code, 
            Duration.ofMinutes(activationCodeExpiryMinutes)
        );
        
        log.info("Activation code generated and stored in Redis for user: {}", userId);
        return code;
    }

    /**
     * Verifica código de activación desde Redis
     * Reemplaza: user.getCodeActivation().equals() y user.isActivationCodeExpired()
     */
    public boolean verifyActivationCode(Long userId, String code) {
        String key = "activation_code:" + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        
        if (storedCode == null || !storedCode.equals(code.trim())) {
            log.warn("Invalid activation code attempt for user: {}", userId);
            return false;
        }
        
        // Código válido - eliminarlo para que sea de un solo uso
        redisTemplate.delete(key);
        log.info("Activation code verified and consumed for user: {}", userId);
        return true;
    }

    // ================= RESET PASSWORD CODE =================

    /**
     * Genera y almacena código de reset password en Redis
     * Reemplaza: user.setCodeResetPassword() y user.setCodeResetPasswordExpiry()
     */
    public String generateAndStoreResetCode(Long userId) {
        String code = generateSixDigitCode();
        String key = "reset_code:" + userId;
        
        redisTemplate.opsForValue().set(
            key, 
            code, 
            Duration.ofMinutes(resetPasswordCodeExpiryMinutes)
        );
        
        log.info("Reset password code generated and stored in Redis for user: {}", userId);
        return code;
    }

    /**
     * Verifica código de reset password desde Redis
     * Reemplaza: user.getCodeResetPassword().equals() y verificación de expiración
     */
    public boolean verifyResetCode(Long userId, String code) {
        String key = "reset_code:" + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        
        if (storedCode == null || !storedCode.equals(code.trim())) {
            log.warn("Invalid reset code attempt for user: {}", userId);
            return false;
        }
        
        // Código válido - eliminarlo para que sea de un solo uso
        redisTemplate.delete(key);
        log.info("Reset code verified and consumed for user: {}", userId);
        return true;
    }

    // ================= UNLOCK CODE (NUEVO) =================

    /**
     * Genera y almacena código de desbloqueo en Redis
     */
    public String generateAndStoreUnlockCode(Long userId) {
        String code = generateSixDigitCode();
        String key = "unlock_code:" + userId;
        
        redisTemplate.opsForValue().set(
            key, 
            code, 
            Duration.ofMinutes(unlockCodeExpiryMinutes)
        );
        
        log.info("Unlock code generated and stored in Redis for user: {}", userId);
        return code;
    }

    /**
     * Verifica código de desbloqueo desde Redis
     */
    public boolean verifyUnlockCode(Long userId, String code) {
        String key = "unlock_code:" + userId;
        String storedCode = redisTemplate.opsForValue().get(key);
        
        if (storedCode == null || !storedCode.equals(code.trim())) {
            log.warn("Invalid unlock code attempt for user: {}", userId);
            return false;
        }
        
        // Código válido - eliminarlo para que sea de un solo uso
        redisTemplate.delete(key);
        log.info("Unlock code verified and consumed for user: {}", userId);
        return true;
    }

    // ================= RATE LIMITING =================

    /**
     * Controla el rate limiting para evitar spam
     * Máximo 3 solicitudes por hora por tipo de token
     */
    public boolean canRequestToken(Long userId, String tokenType) {
        String rateLimitKey = tokenType + "_rate_limit:" + userId;
        String count = redisTemplate.opsForValue().get(rateLimitKey);
        
        if (count == null) {
            // Primera solicitud
            redisTemplate.opsForValue().set(rateLimitKey, "1", Duration.ofHours(1));
            return true;
        }
        
        int currentCount = Integer.parseInt(count);
        if (currentCount >= MAX_REQUESTS_PER_HOUR) {
            log.warn("Rate limit exceeded for user {} and token type {}", userId, tokenType);
            return false;
        }
        
        // Incrementar contador
        redisTemplate.opsForValue().increment(rateLimitKey, 1);
        return true;
    }

    // ================= MÉTODOS DE UTILIDAD =================

    /**
     * Verifica si existe un código activo sin consumirlo
     */
    public boolean hasActiveActivationCode(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("activation_code:" + userId));
    }

    public boolean hasActiveResetCode(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("reset_code:" + userId));
    }

    public boolean hasActiveUnlockCode(Long userId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey("unlock_code:" + userId));
    }

    /**
     * Obtiene tiempo de vida restante del código en minutos
     */
    public long getActivationCodeTTL(Long userId) {
        return redisTemplate.getExpire("activation_code:" + userId, TimeUnit.MINUTES);
    }

    public long getResetCodeTTL(Long userId) {
        return redisTemplate.getExpire("reset_code:" + userId, TimeUnit.MINUTES);
    }

    public long getUnlockCodeTTL(Long userId) {
        return redisTemplate.getExpire("unlock_code:" + userId, TimeUnit.MINUTES);
    }

    /**
     * Invalida códigos manualmente (útil para casos especiales)
     */
    public void invalidateActivationCode(Long userId) {
        redisTemplate.delete("activation_code:" + userId);
        log.info("Activation code manually invalidated for user: {}", userId);
    }

    public void invalidateResetCode(Long userId) {
        redisTemplate.delete("reset_code:" + userId);
        log.info("Reset code manually invalidated for user: {}", userId);
    }

    public void invalidateUnlockCode(Long userId) {
        redisTemplate.delete("unlock_code:" + userId);
        log.info("Unlock code manually invalidated for user: {}", userId);
    }

    /**
     * Limpia todos los tokens de un usuario (útil cuando se desactiva cuenta)
     */
    public void invalidateAllUserTokens(Long userId) {
        invalidateActivationCode(userId);
        invalidateResetCode(userId);
        invalidateUnlockCode(userId);
        
        // Limpiar rate limiting también
        redisTemplate.delete("activation_rate_limit:" + userId);
        redisTemplate.delete("reset_rate_limit:" + userId);
        redisTemplate.delete("unlock_rate_limit:" + userId);
        
        log.warn("ALL tokens invalidated for user: {}", userId);
    }

    /**
     * Genera código de 6 dígitos
     * Mantiene compatibilidad con tu EmailService existente
     */
    private String generateSixDigitCode() {
        return String.format("%06d", new Random().nextInt(999999));
    }

    /**
     * Para debugging - obtiene información de todos los tokens de un usuario
     */
    public TokensStatusDTO getUserTokensStatus(Long userId) {
        return TokensStatusDTO.builder()
            .userId(userId)
            .hasActivationCode(hasActiveActivationCode(userId))
            .hasResetCode(hasActiveResetCode(userId))
            .hasUnlockCode(hasActiveUnlockCode(userId))
            .activationCodeTTL(getActivationCodeTTL(userId))
            .resetCodeTTL(getResetCodeTTL(userId))
            .unlockCodeTTL(getUnlockCodeTTL(userId))
            .build();
    }

    // DTO para status de tokens
    @lombok.Builder
    @lombok.Data
    public static class TokensStatusDTO {
        private Long userId;
        private boolean hasActivationCode;
        private boolean hasResetCode;
        private boolean hasUnlockCode;
        private long activationCodeTTL;
        private long resetCodeTTL;
        private long unlockCodeTTL;
    }
}