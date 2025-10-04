package com.e_commerce.e_commerce_back.services.implementation;

import com.e_commerce.e_commerce_back.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Servicio para manejo de sesiones JWT en Redis
 * Gestiona access tokens, refresh tokens, sesiones activas y revocación
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JwtSessionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final JwtUtil jwtUtil;

    // Configuraciones desde application.properties
    @Value("${app.jwt.expiration}")
    private Long jwtExpirationMs;

    @Value("${app.jwt.refresh-expiration}")
    private Long refreshExpirationMs;

    @Value("${app.security.max-concurrent-sessions:3}")
    private Integer maxConcurrentSessions;

    // Prefijos de keys para Redis
    private static final String ACCESS_TOKEN_PREFIX = "access_token:";
    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final String USER_SESSIONS_PREFIX = "user_sessions:";
    private static final String TOKEN_BLACKLIST_PREFIX = "blacklist:";
    private static final String REFRESH_BY_SESSION_PREFIX = "refresh_by_session:"; // sid -> refresh
    private static final String SESSION_BY_REFRESH_PREFIX = "session_by_refresh:"; // refresh -> sid

    // ================= SESSION MANAGEMENT =================

    /**
     * Crea una nueva sesión completa (access + refresh token)
     */
    public SessionTokens createSession(Long userId, String email, String userAgent, String ipAddress) {
        String sessionId = UUID.randomUUID().toString();

        // Generar tokens JWT
        String accessToken = jwtUtil.generateAccessToken(email, userId, sessionId);
        String refreshToken = UUID.randomUUID().toString().replace("-", "");

        // Calcular TTL
        long accessTtlSeconds = jwtExpirationMs / 1000;
        long refreshTtlSeconds = refreshExpirationMs / 1000;

        // Almacenar access token con metadata
        String accessKey = ACCESS_TOKEN_PREFIX + sessionId;
        SessionMetadata accessMetadata = SessionMetadata.builder()
                .userId(userId)
                .email(email)
                .sessionId(sessionId)
                .token(accessToken)
                .tokenType("ACCESS")
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(accessTtlSeconds))
                .build();

        redisTemplate.opsForValue().set(accessKey, accessMetadata, Duration.ofSeconds(accessTtlSeconds));

        // Almacenar refresh token
        String refreshKey = REFRESH_TOKEN_PREFIX + refreshToken;
        SessionMetadata refreshMetadata = SessionMetadata.builder()
                .userId(userId)
                .email(email)
                .sessionId(sessionId)
                .token(refreshToken)
                .tokenType("REFRESH")
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(refreshTtlSeconds))
                .build();

        redisTemplate.opsForValue().set(refreshKey, refreshMetadata, Duration.ofSeconds(refreshTtlSeconds));

        // Índices para evitar KEYS: sid -> refresh, refresh -> sid
        redisTemplate.opsForValue().set(REFRESH_BY_SESSION_PREFIX + sessionId, refreshToken, Duration.ofSeconds(refreshTtlSeconds));
        redisTemplate.opsForValue().set(SESSION_BY_REFRESH_PREFIX + refreshToken, sessionId, Duration.ofSeconds(refreshTtlSeconds));

        // Registrar sesión en el índice del usuario
        addSessionToUserIndex(userId, sessionId, accessTtlSeconds);

        // Controlar sesiones concurrentes
        enforceConcurrentSessionsLimit(userId);

        log.info("Nueva sesión creada - UserId: {}, SessionId: {}, IP: {}", userId, sessionId, ipAddress);

        return SessionTokens.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .sessionId(sessionId)
                .expiresIn(accessTtlSeconds)
                .build();
    }

    /**
     * Valida un access token
     */
    public SessionValidation validateAccessToken(String token) {
        try {
            // Verificar si está en blacklist
            if (isTokenBlacklisted(token)) {
                return SessionValidation.invalid("Token revocado");
            }

            // Extraer userId del JWT (claim uid)
            Long userId = jwtUtil.extractUserId(token);

            // Buscar sesión en Redis
            if (userId == null) {
                return SessionValidation.invalid("Token sin uid");
            }

            SessionMetadata metadata = findSessionByAccessToken(userId, token);

            if (metadata == null) {
                return SessionValidation.invalid("Sesión no encontrada en Redis");
            }

            // Verificar expiración
            if (Instant.now().isAfter(metadata.getExpiresAt())) {
                return SessionValidation.invalid("Token expirado");
            }

            return SessionValidation.valid(metadata);

        } catch (Exception e) {
            log.error("Error validando access token: {}", e.getMessage());
            return SessionValidation.invalid("Token inválido");
        }
    }

    /**
     * Refresca un access token usando un refresh token
     */
    public SessionTokens refreshAccessToken(String refreshToken) {
        String refreshKey = REFRESH_TOKEN_PREFIX + refreshToken;
        SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(refreshKey);

        if (metadata == null) {
            log.warn("Refresh token no encontrado: {}", refreshToken);
            throw new RuntimeException("Refresh token inválido");
        }

        // Verificar expiración
        if (Instant.now().isAfter(metadata.getExpiresAt())) {
            log.warn("Refresh token expirado para sesión: {}", metadata.getSessionId());
            throw new RuntimeException("Refresh token expirado");
        }

        // Revocar access token anterior
        revokeAccessToken(metadata.getSessionId());

        // Generar nuevo access token
        String newAccessToken = jwtUtil.generateAccessToken(
                metadata.getEmail(),
                metadata.getUserId(),
                metadata.getSessionId());
        long accessTtlSeconds = jwtExpirationMs / 1000;

        // Almacenar nuevo access token
        String accessKey = ACCESS_TOKEN_PREFIX + metadata.getSessionId();
        SessionMetadata newAccessMetadata = SessionMetadata.builder()
                .userId(metadata.getUserId())
                .sessionId(metadata.getSessionId())
                .token(newAccessToken)
                .tokenType("ACCESS")
                .userAgent(metadata.getUserAgent())
                .ipAddress(metadata.getIpAddress())
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(accessTtlSeconds))
                .build();

        redisTemplate.opsForValue().set(accessKey, newAccessMetadata, Duration.ofSeconds(accessTtlSeconds));

        log.info("Access token refrescado - SessionId: {}, UserId: {}",
                metadata.getSessionId(), metadata.getUserId());

        return SessionTokens.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .sessionId(metadata.getSessionId())
                .expiresIn(accessTtlSeconds)
                .build();
    }
    

    /**
     * Cierra una sesión específica (MEJORADO)
     */
    public void closeSession(String sessionId) {
        // Obtener metadata del access token
        String accessKey = ACCESS_TOKEN_PREFIX + sessionId;
        SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(accessKey);

        if (metadata != null) {
            // Agregar access token a blacklist
            blacklistTokenInternal(metadata.getToken(), metadata.getExpiresAt());

            // Eliminar access token
            redisTemplate.delete(accessKey);

            // Buscar y eliminar refresh token usando índice directo (sin KEYS)
            String refreshToken = (String) redisTemplate.opsForValue().get(REFRESH_BY_SESSION_PREFIX + sessionId);
            if (refreshToken != null) {
                String refreshStoreKey = REFRESH_TOKEN_PREFIX + refreshToken;
                redisTemplate.delete(refreshStoreKey);
                redisTemplate.delete(REFRESH_BY_SESSION_PREFIX + sessionId);
                redisTemplate.delete(SESSION_BY_REFRESH_PREFIX + refreshToken);
            }

            // Remover de índice de usuario
            removeSessionFromUserIndex(metadata.getUserId(), sessionId);

            log.info("Sesión cerrada - SessionId: {}, UserId: {}", sessionId, metadata.getUserId());
        } else {
            log.warn("Sesión no encontrada para cerrar: {}", sessionId);
        }
    }

    /**
     * Cierra todas las sesiones de un usuario
     */
    public void closeAllUserSessions(Long userId) {
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        Set<Object> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);

        if (sessionIds != null && !sessionIds.isEmpty()) {
            log.info("Cerrando {} sesiones para usuario: {}", sessionIds.size(), userId);

            for (Object sessionIdObj : sessionIds) {
                String sessionId = sessionIdObj.toString();
                closeSession(sessionId);
            }

            // Limpiar índice
            redisTemplate.delete(userSessionsKey);
        } else {
            log.info("No se encontraron sesiones activas para usuario: {}", userId);
        }
    }

    /**
     * Obtiene todas las sesiones activas de un usuario
     */
    public List<SessionInfo> getUserActiveSessions(Long userId) {
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        Set<Object> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);

        if (sessionIds == null || sessionIds.isEmpty()) {
            return Collections.emptyList();
        }

        return sessionIds.stream()
                .map(sessionIdObj -> {
                    String sessionId = sessionIdObj.toString();
                    String accessKey = ACCESS_TOKEN_PREFIX + sessionId;
                    SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(accessKey);

                    if (metadata != null) {
                        return SessionInfo.builder()
                                .sessionId(sessionId)
                                .userAgent(metadata.getUserAgent())
                                .ipAddress(metadata.getIpAddress())
                                .createdAt(metadata.getCreatedAt())
                                .expiresAt(metadata.getExpiresAt())
                                .isActive(Instant.now().isBefore(metadata.getExpiresAt()))
                                .build();
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    // ================= BLACKLIST MANAGEMENT =================

    /**
     * Agrega token a blacklist (INTERNO - uso privado)
     */
    private void blacklistTokenInternal(String token, Instant expiresAt) {
        Duration ttl = Duration.between(Instant.now(), expiresAt);

        if (ttl.isPositive()) {
            String key = TOKEN_BLACKLIST_PREFIX + token;
            redisTemplate.opsForValue().set(key, "revoked", ttl);
            log.debug("Token agregado a blacklist (TTL: {} segundos)", ttl.getSeconds());
        }
    }

    /**
     * Verifica si token está en blacklist (PÚBLICO)
     */
    public boolean isTokenBlacklisted(String token) {
        String key = TOKEN_BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * Agrega access token a blacklist (público para uso externo)
     */
    public void blacklistAccessToken(String token) {
        try {
            java.util.Date expiration = jwtUtil.extractExpiration(token);
            Duration ttl = Duration.between(Instant.now(), expiration.toInstant());

            if (ttl.isPositive()) {
                String key = TOKEN_BLACKLIST_PREFIX + token;
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
     * Revoca access token por sessionId
     */
    private void revokeAccessToken(String sessionId) {
        String accessKey = ACCESS_TOKEN_PREFIX + sessionId;
        SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(accessKey);

        if (metadata != null) {
            blacklistTokenInternal(metadata.getToken(), metadata.getExpiresAt());
        }
    }

    // ================= USER SESSION INDEX =================

    /**
     * Agrega sesión al índice de usuario
     */
    private void addSessionToUserIndex(Long userId, String sessionId, long ttlSeconds) {
        String key = USER_SESSIONS_PREFIX + userId;
        redisTemplate.opsForSet().add(key, sessionId);
        redisTemplate.expire(key, Duration.ofSeconds(ttlSeconds + 3600)); // +1 hora extra
    }

    /**
     * Remueve sesión del índice de usuario
     */
    private void removeSessionFromUserIndex(Long userId, String sessionId) {
        String key = USER_SESSIONS_PREFIX + userId;
        redisTemplate.opsForSet().remove(key, sessionId);
    }

    /**
     * Limita sesiones concurrentes
     */
    private void enforceConcurrentSessionsLimit(Long userId) {
        String key = USER_SESSIONS_PREFIX + userId;
        Long sessionCount = redisTemplate.opsForSet().size(key);

        if (sessionCount != null && sessionCount > maxConcurrentSessions) {
            // Obtener todas las sesiones
            List<SessionInfo> sessions = getUserActiveSessions(userId);

            // Ordenar por fecha de creación (más antiguas primero)
            sessions.sort(Comparator.comparing(SessionInfo::getCreatedAt));

            // Cerrar sesiones más antiguas
            int sessionsToClose = sessionCount.intValue() - maxConcurrentSessions;
            for (int i = 0; i < sessionsToClose && i < sessions.size(); i++) {
                closeSession(sessions.get(i).getSessionId());
                log.info("Sesión antigua cerrada por límite de concurrencia - UserId: {}", userId);
            }
        }
    }

    /**
     * Busca sesión por access token
     */
    private SessionMetadata findSessionByAccessToken(Long userId, String token) {
        String userSessionsKey = USER_SESSIONS_PREFIX + userId;
        Set<Object> sessionIds = redisTemplate.opsForSet().members(userSessionsKey);

        if (sessionIds != null) {
            for (Object sessionIdObj : sessionIds) {
                String sessionId = sessionIdObj.toString();
                String accessKey = ACCESS_TOKEN_PREFIX + sessionId;
                SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(accessKey);

                if (metadata != null && metadata.getToken().equals(token)) {
                    return metadata;
                }
            }
        }
        return null;
    }

    // ================= PUBLIC SESSION QUERY METHODS =================

    /**
     * Encuentra sessionId por access token (público para logout)
     */
    public String findSessionIdByAccessToken(String accessToken) {
        try {
            // Extraer userId del token
            Long userId = jwtUtil.extractUserId(accessToken);
            if (userId == null) {
                return null;
            }

            // Buscar en las sesiones del usuario
            List<SessionInfo> sessions = getUserActiveSessions(userId);
            for (SessionInfo session : sessions) {
                String accessKey = ACCESS_TOKEN_PREFIX + session.getSessionId();
                SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(accessKey);
                if (metadata != null && accessToken.equals(metadata.getToken())) {
                    return session.getSessionId();
                }
            }
            return null;
        } catch (Exception e) {
            log.warn("Error finding session by access token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Obtiene metadata de sesión por sessionId
     */
    public SessionMetadata getSessionMetadata(String sessionId) {
        try {
            String accessKey = ACCESS_TOKEN_PREFIX + sessionId;
            return (SessionMetadata) redisTemplate.opsForValue().get(accessKey);
        } catch (Exception e) {
            log.warn("Error obteniendo metadata de sesión {}: {}", sessionId, e.getMessage());
            return null;
        }
    }

    /**
     * Obtiene userId desde un access token (útil para validaciones)
     */
    public Long getUserIdFromAccessToken(String accessToken) {
        try {
            String userIdStr = jwtUtil.extractUsername(accessToken);
            return Long.parseLong(userIdStr);
        } catch (Exception e) {
            log.warn("Error extrayendo userId de access token: {}", e.getMessage());
            return null;
        }
    }

    // ================= BATCH OPERATIONS =================

    /**
     * Cierra todas las sesiones excepto la especificada
     */
    public void closeAllOtherUserSessions(Long userId, String currentSessionId) {
        List<SessionInfo> sessions = getUserActiveSessions(userId);

        int closedCount = 0;
        for (SessionInfo session : sessions) {
            if (!session.getSessionId().equals(currentSessionId)) {
                closeSession(session.getSessionId());
                closedCount++;
            }
        }

        log.info("Cerradas {} sesiones de otros dispositivos para usuario: {}", closedCount, userId);
    }

    /**
     * Obtiene estadísticas de sesiones activas
     */
    public SessionStats getSessionStats(Long userId) {
        List<SessionInfo> sessions = getUserActiveSessions(userId);

        long activeSessions = sessions.stream()
                .filter(SessionInfo::isActive)
                .count();

        long totalSessions = sessions.size();

        return SessionStats.builder()
                .userId(userId)
                .totalSessions(totalSessions)
                .activeSessions(activeSessions)
                .maxAllowedSessions(maxConcurrentSessions)
                .build();
    }

    // ================= MAINTENANCE METHODS =================

    /**
     * Limpia sesiones expiradas (para uso administrativo o scheduled tasks)
     */
    public void cleanupExpiredSessions() {
        try {
            int totalCleaned = 0;

            // Limpiar access tokens expirados
            Set<String> accessKeys = redisTemplate.keys(ACCESS_TOKEN_PREFIX + "*");
            if (accessKeys != null) {
                int cleanedCount = 0;
                for (String key : accessKeys) {
                    SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(key);
                    if (metadata != null && Instant.now().isAfter(metadata.getExpiresAt())) {
                        redisTemplate.delete(key);
                        cleanedCount++;
                    }
                }
                totalCleaned += cleanedCount;
                log.info("Limpieza de sesiones: {} access tokens expirados removidos", cleanedCount);
            }

            // Limpiar refresh tokens expirados
            Set<String> refreshKeys = redisTemplate.keys(REFRESH_TOKEN_PREFIX + "*");
            if (refreshKeys != null) {
                int cleanedCount = 0;
                for (String key : refreshKeys) {
                    SessionMetadata metadata = (SessionMetadata) redisTemplate.opsForValue().get(key);
                    if (metadata != null && Instant.now().isAfter(metadata.getExpiresAt())) {
                        redisTemplate.delete(key);
                        cleanedCount++;
                    }
                }
                totalCleaned += cleanedCount;
                log.info("Limpieza de sesiones: {} refresh tokens expirados removidos", cleanedCount);
            }

            // Limpiar índices de usuario vacíos
            Set<String> userSessionKeys = redisTemplate.keys(USER_SESSIONS_PREFIX + "*");
            if (userSessionKeys != null) {
                int emptyIndicesCleaned = 0;
                for (String key : userSessionKeys) {
                    Long size = redisTemplate.opsForSet().size(key);
                    if (size == null || size == 0) {
                        redisTemplate.delete(key);
                        emptyIndicesCleaned++;
                    }
                }
                log.info("Limpieza de sesiones: {} índices vacíos removidos", emptyIndicesCleaned);
            }

            log.info("Limpieza de sesiones completada: {} tokens expirados removidos en total", totalCleaned);

        } catch (Exception e) {
            log.error("Error en limpieza de sesiones expiradas: {}", e.getMessage());
        }
    }

    /**
     * Verifica la salud del servicio de sesiones
     */
    public SessionHealthCheck healthCheck() {
        try {
            // Test de conexión a Redis
            String testKey = "health_check_" + UUID.randomUUID();
            redisTemplate.opsForValue().set(testKey, "test", Duration.ofSeconds(10));
            String testValue = (String) redisTemplate.opsForValue().get(testKey);
            boolean redisConnected = "test".equals(testValue);

            // Contar sesiones activas aproximadas
            Set<String> accessKeys = redisTemplate.keys(ACCESS_TOKEN_PREFIX + "*");
            long activeSessions = accessKeys != null ? accessKeys.size() : 0;

            // Limpiar clave de test
            redisTemplate.delete(testKey);

            return SessionHealthCheck.builder()
                    .status("UP")
                    .redisConnected(redisConnected)
                    .activeSessions(activeSessions)
                    .timestamp(Instant.now())
                    .build();

        } catch (Exception e) {
            return SessionHealthCheck.builder()
                    .status("DOWN")
                    .redisConnected(false)
                    .activeSessions(0)
                    .timestamp(Instant.now())
                    .error(e.getMessage())
                    .build();
        }
    }

    // ================= DTOs =================

    @lombok.Builder
    @lombok.Data
    public static class SessionTokens {
        private String accessToken;
        private String refreshToken;
        private String sessionId;
        private Long expiresIn;
    }

    @lombok.Builder
    @lombok.Data
    @lombok.AllArgsConstructor
    @lombok.NoArgsConstructor
    public static class SessionMetadata implements java.io.Serializable {
        private Long userId;
        private String email;
        private String sessionId;
        private String token;
        private String tokenType;
        private String userAgent;
        private String ipAddress;
        private Instant createdAt;
        private Instant expiresAt;
    }

    @lombok.Builder
    @lombok.Data
    public static class SessionInfo {
        private String sessionId;
        private String userAgent;
        private String ipAddress;
        private Instant createdAt;
        private Instant expiresAt;
        private boolean isActive;
    }

    @lombok.Builder
    @lombok.Data
    public static class SessionStats {
        private Long userId;
        private long totalSessions;
        private long activeSessions;
        private int maxAllowedSessions;
    }

    @lombok.Builder
    @lombok.Data
    public static class SessionHealthCheck {
        private String status;
        private boolean redisConnected;
        private long activeSessions;
        private Instant timestamp;
        private String error;
    }

    @lombok.Builder
    @lombok.Data
    public static class SessionValidation {
        private boolean valid;
        private String reason;
        private SessionMetadata metadata;

        public static SessionValidation valid(SessionMetadata metadata) {
            return SessionValidation.builder()
                    .valid(true)
                    .metadata(metadata)
                    .build();
        }

        public static SessionValidation invalid(String reason) {
            return SessionValidation.builder()
                    .valid(false)
                    .reason(reason)
                    .build();
        }
    }
}