package com.e_commerce.e_commerce_back.services.implementation;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * Servicio para manejo de bloqueo de cuentas por intentos fallidos de login usando Redis
 * Implementa operaciones atómicas y gestión temporal de bloqueos
 * 
 * Ventajas de usar Redis vs Base de Datos:
 * - Expiración automática (TTL) sin necesidad de jobs de limpieza
 * - Alto rendimiento para operaciones de lectura/escritura frecuentes
 * - Operaciones atómicas (INCR) para contadores sin race conditions
 * - Menor carga en la base de datos principal
 * - Escalabilidad horizontal más sencilla
 */
@Service
@Slf4j
public class AccountLockoutRedisService {

    private final RedisTemplate<String, String> redisTemplate;

    // Constructor con @Qualifier para especificar el bean correcto
    public AccountLockoutRedisService(
            @Qualifier("customStringRedisTemplate") RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Configuraciones desde application.properties
    @Value("${app.security.max-failed-attempts:5}")
    private Integer maxFailedAttempts;

    @Value("${app.security.lockout-duration-minutes:15}")
    private Integer lockoutDurationMinutes;

    @Value("${app.security.failed-attempts-window-minutes:30}")
    private Integer failedAttemptsWindowMinutes;

    // Prefijos de keys para Redis
    private static final String FAILED_ATTEMPTS_PREFIX = "failed_attempts:";
    private static final String ACCOUNT_LOCKED_PREFIX = "account_locked:";
    private static final String LOCKOUT_HISTORY_PREFIX = "lockout_history:";

    // ================= GESTIÓN DE INTENTOS FALLIDOS =================

    /**
     * Registra un intento fallido de login
     * Usa operaciones atómicas de Redis para evitar race conditions
     * 
     * @param userId ID del usuario
     * @return número actual de intentos fallidos
     */
    public int recordFailedAttempt(Long userId) {
        String key = FAILED_ATTEMPTS_PREFIX + userId;
        
        // Incrementar atómicamente el contador
        Long attempts = redisTemplate.opsForValue().increment(key);
        
        if (attempts == null) {
            log.error("Error: Redis increment retornó null para userId: {}", userId);
            attempts = 1L;
        }
        
        // Si es el primer intento, establecer TTL para la ventana de tiempo
        if (attempts == 1) {
            redisTemplate.expire(key, Duration.ofMinutes(failedAttemptsWindowMinutes));
            log.debug("Primera tentativa fallida para usuario: {} - TTL: {} minutos", 
                userId, failedAttemptsWindowMinutes);
        }
        
        log.warn("Intento fallido registrado para usuario: {} - Total: {}/{}", 
            userId, attempts, maxFailedAttempts);
        
        // Si alcanza el máximo, bloquear la cuenta
        if (attempts >= maxFailedAttempts) {
            lockAccount(userId);
        }
        
        return attempts.intValue();
    }

    /**
     * Obtiene el número de intentos fallidos actuales
     * 
     * @param userId ID del usuario
     * @return número de intentos fallidos
     */
    public int getFailedAttempts(Long userId) {
        String key = FAILED_ATTEMPTS_PREFIX + userId;
        String value = redisTemplate.opsForValue().get(key);
        
        if (value == null) {
            return 0;
        }
        
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            log.error("Formato inválido de intentos fallidos para usuario {}: {}", userId, value);
            return 0;
        }
    }

    /**
     * Obtiene intentos restantes antes del bloqueo
     * 
     * @param userId ID del usuario
     * @return número de intentos restantes
     */
    public int getRemainingAttempts(Long userId) {
        int currentAttempts = getFailedAttempts(userId);
        return Math.max(0, maxFailedAttempts - currentAttempts);
    }

    /**
     * Resetea los intentos fallidos (usado tras login exitoso)
     * 
     * @param userId ID del usuario
     */
    public void resetFailedAttempts(Long userId) {
        String key = FAILED_ATTEMPTS_PREFIX + userId;
        Boolean deleted = redisTemplate.delete(key);
        
        if (Boolean.TRUE.equals(deleted)) {
            log.info("Intentos fallidos reseteados para usuario: {}", userId);
        }
    }

    // ================= GESTIÓN DE BLOQUEO DE CUENTA =================

    /**
     * Bloquea una cuenta por el tiempo configurado
     * 
     * @param userId ID del usuario
     */
    public void lockAccount(Long userId) {
        String key = ACCOUNT_LOCKED_PREFIX + userId;
        Instant lockUntil = Instant.now().plus(Duration.ofMinutes(lockoutDurationMinutes));
        
        // Almacenar timestamp de desbloqueo
        redisTemplate.opsForValue().set(
            key, 
            lockUntil.toString(), 
            Duration.ofMinutes(lockoutDurationMinutes)
        );
        
        // Registrar en historial
        recordLockoutHistory(userId, lockUntil);
        
        log.warn("Cuenta bloqueada para usuario: {} hasta: {} ({} minutos)", 
            userId, lockUntil, lockoutDurationMinutes);
    }

    /**
     * Verifica si una cuenta está bloqueada
     * 
     * @param userId ID del usuario
     * @return true si la cuenta está bloqueada
     */
    public boolean isAccountLocked(Long userId) {
        String key = ACCOUNT_LOCKED_PREFIX + userId;
        String lockUntilStr = redisTemplate.opsForValue().get(key);
        
        if (lockUntilStr == null) {
            return false;
        }
        
        try {
            Instant lockUntil = Instant.parse(lockUntilStr);
            boolean isLocked = Instant.now().isBefore(lockUntil);
            
            if (!isLocked) {
                // El bloqueo expiró, limpiar la key (aunque Redis lo hará automáticamente)
                redisTemplate.delete(key);
            }
            
            return isLocked;
        } catch (Exception e) {
            log.error("Error parseando timestamp de bloqueo para usuario {}: {}", userId, lockUntilStr);
            // En caso de error, asumir que no está bloqueado y limpiar la key corrupta
            redisTemplate.delete(key);
            return false;
        }
    }

    /**
     * Obtiene el tiempo restante de bloqueo
     * 
     * @param userId ID del usuario
     * @return Duration con el tiempo restante, o Duration.ZERO si no está bloqueado
     */
    public Duration getRemainingLockoutTime(Long userId) {
        String key = ACCOUNT_LOCKED_PREFIX + userId;
        String lockUntilStr = redisTemplate.opsForValue().get(key);
        
        if (lockUntilStr == null) {
            return Duration.ZERO;
        }
        
        try {
            Instant lockUntil = Instant.parse(lockUntilStr);
            Instant now = Instant.now();
            
            if (now.isBefore(lockUntil)) {
                return Duration.between(now, lockUntil);
            }
        } catch (Exception e) {
            log.error("Error calculando tiempo restante de bloqueo para usuario {}: {}", userId, lockUntilStr);
        }
        
        return Duration.ZERO;
    }

    /**
     * Desbloquea manualmente una cuenta
     * 
     * @param userId ID del usuario
     */
    public void unlockAccount(Long userId) {
        String lockKey = ACCOUNT_LOCKED_PREFIX + userId;
        String attemptsKey = FAILED_ATTEMPTS_PREFIX + userId;
        
        redisTemplate.delete(lockKey);
        redisTemplate.delete(attemptsKey);
        
        log.info("Cuenta desbloqueada manualmente para usuario: {}", userId);
    }

    // ================= HISTORIAL DE BLOQUEOS =================

    /**
     * Registra un bloqueo en el historial (para auditoría)
     * Mantiene los últimos bloqueos con TTL de 30 días
     * 
     * @param userId ID del usuario
     * @param lockUntil Timestamp hasta cuando está bloqueado
     */
    private void recordLockoutHistory(Long userId, Instant lockUntil) {
        String key = LOCKOUT_HISTORY_PREFIX + userId;
        String timestamp = Instant.now().toString();
        
        // Usar una lista para mantener historial
        redisTemplate.opsForList().rightPush(key, timestamp);
        
        // Mantener solo los últimos 10 bloqueos
        redisTemplate.opsForList().trim(key, -10, -1);
        
        // Establecer TTL de 30 días para el historial
        redisTemplate.expire(key, Duration.ofDays(30));
        
        log.debug("Bloqueo registrado en historial para usuario: {}", userId);
    }

    /**
     * Obtiene el número de veces que una cuenta ha sido bloqueada (últimos 30 días)
     * 
     * @param userId ID del usuario
     * @return número de bloqueos en el historial
     */
    public long getLockoutCount(Long userId) {
        String key = LOCKOUT_HISTORY_PREFIX + userId;
        Long count = redisTemplate.opsForList().size(key);
        return count != null ? count : 0;
    }

    /**
     * Limpia el historial de bloqueos
     * 
     * @param userId ID del usuario
     */
    public void clearLockoutHistory(Long userId) {
        String key = LOCKOUT_HISTORY_PREFIX + userId;
        redisTemplate.delete(key);
        log.info("Historial de bloqueos limpiado para usuario: {}", userId);
    }

    // ================= MÉTODOS DE UTILIDAD =================

    /**
     * Obtiene información completa del estado de bloqueo de un usuario
     * 
     * @param userId ID del usuario
     * @return DTO con el estado completo
     */
    public LockoutStatusDTO getLockoutStatus(Long userId) {
        boolean isLocked = isAccountLocked(userId);
        int failedAttempts = getFailedAttempts(userId);
        int remainingAttempts = getRemainingAttempts(userId);
        Duration remainingLockTime = getRemainingLockoutTime(userId);
        long lockoutCount = getLockoutCount(userId);
        
        return LockoutStatusDTO.builder()
            .userId(userId)
            .isLocked(isLocked)
            .failedAttempts(failedAttempts)
            .remainingAttempts(remainingAttempts)
            .remainingLockoutMinutes(remainingLockTime.toMinutes())
            .totalLockoutsLast30Days(lockoutCount)
            .maxFailedAttempts(maxFailedAttempts)
            .lockoutDurationMinutes(lockoutDurationMinutes)
            .build();
    }

    /**
     * Limpia todos los datos de bloqueo de un usuario (uso administrativo)
     * 
     * @param userId ID del usuario
     */
    public void clearAllLockoutData(Long userId) {
        unlockAccount(userId);
        clearLockoutHistory(userId);
        log.warn("TODOS los datos de bloqueo eliminados para usuario: {}", userId);
    }

    /**
     * Verifica si un usuario debería ser bloqueado basado en intentos actuales
     * 
     * @param userId ID del usuario
     * @return true si debería bloquearse
     */
    public boolean shouldLockAccount(Long userId) {
        return getFailedAttempts(userId) >= maxFailedAttempts;
    }

    /**
     * Obtiene el TTL restante de la ventana de intentos fallidos
     * 
     * @param userId ID del usuario
     * @return Duration con el tiempo restante de la ventana
     */
    public Duration getFailedAttemptsWindowRemaining(Long userId) {
        String key = FAILED_ATTEMPTS_PREFIX + userId;
        Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
        
        if (ttl != null && ttl > 0) {
            return Duration.ofSeconds(ttl);
        }
        return Duration.ZERO;
    }

    // ================= DTO =================

    /**
     * DTO para el estado de bloqueo de una cuenta
     */
    @lombok.Builder
    @lombok.Data
    public static class LockoutStatusDTO {
        private Long userId;
        private boolean isLocked;
        private int failedAttempts;
        private int remainingAttempts;
        private long remainingLockoutMinutes;
        private long totalLockoutsLast30Days;
        private int maxFailedAttempts;
        private int lockoutDurationMinutes;
    }
}
