package com.e_commerce.e_commerce_back.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.e_commerce.e_commerce_back.services.implementation.TokenRedisService;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Utilidad para manejar tokens JWT
 * Implementa las mejores prácticas de seguridad para JWT
 */
@Component
@Slf4j
public class JwtUtil {


    private TokenRedisService tokenRedisService;

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.expiration}")
    private Long expiration;

    @Value("${app.jwt.refresh-expiration}")
    private Long refreshExpiration; // Por ejemplo: 604800000 (7 días en milisegundos)

    /**
     * Genera la clave secreta para firmar los tokens
     */

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    /**
     * Extrae el username del token
     */

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extrae la fecha de expiración del token
     */

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrae un claim específico del token
     */

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extrae todos los claims del token
     */

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("Token JWT expirado: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.warn("Token JWT no soportado: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.warn("Token JWT malformado: {}", e.getMessage());
            throw e;
        } catch (SecurityException e) {
            log.warn("Firma JWT inválida: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.warn("Token JWT vacío: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Verifica si el token ha expirado
     */

    public Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Genera un token para el usuario
     */

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Genera un token con claims adicionales
     */

    public String generateToken(UserDetails userDetails, Map<String, Object> extraClaims) {
        Map<String, Object> claims = new HashMap<>(extraClaims);
        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Crea el token JWT
     */

    private String createToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Valida el token
     */

    public Boolean validateToken(String token, UserDetails userDetails) {
        try {

            // En tu JwtAuthenticationFilter, antes de validar el token:
            if (tokenRedisService.isTokenBlacklisted(token)) {
                log.warn("Token en blacklist detectado");
                return false; // O manejar como token inválido
            }

            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            log.error("Error validando token JWT: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Valida si el token es válido (sin verificar usuario)
     */
    public Boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            log.error("Token JWT inválido: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene el tiempo restante de vida del token en milisegundos
     */
    public Long getTokenRemainingTime(String token) {
        try {
            Date expiration = extractExpiration(token);
            return expiration.getTime() - System.currentTimeMillis();
        } catch (Exception e) {
            return 0L;
        }
    }

    /**
     * Genera un refresh token para el usuario
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh"); // Identificador del tipo de token
        return createRefreshToken(claims, userDetails.getUsername());
    }

    /**
     * Crea el refresh token JWT con mayor tiempo de expiración
     */

    private String createRefreshToken(Map<String, Object> claims, String subject) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshExpiration);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Valida si el refresh token es válido
     */
    public Boolean isValidRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);

            // Verificar que es un refresh token
            String tokenType = claims.get("type", String.class);
            if (!"refresh".equals(tokenType)) {
                log.warn("Token no es un refresh token");
                return false;
            }

            // Verificar que no ha expirado
            return !isTokenExpired(token);

        } catch (Exception e) {
            log.error("Refresh token inválido: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Genera un access token (método específico para diferenciarlo del refresh)
     */

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "access"); // Identificador del tipo de token
        return createToken(claims, userDetails.getUsername());
    }

    /**
     * Valida que el token sea un access token válido
     */

    public Boolean isValidAccessToken(String token) {
        try {
            Claims claims = extractAllClaims(token);

            // Verificar que es un access token
            String tokenType = claims.get("type", String.class);
            if (!"access".equals(tokenType)) {
                log.warn("Token no es un access token");
                return false;
            }

            return !isTokenExpired(token);

        } catch (Exception e) {
            log.error("Access token inválido: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Obtiene el tiempo de expiración del access token en segundos
     */
    public Long getAccessTokenExpiration() {
        return expiration / 1000; // Convertir de milisegundos a segundos
    }

    /**
     * Obtiene el tiempo de expiración del refresh token en días
     */
    public Long getRefreshTokenExpirationDays() {
        return refreshExpiration / (1000 * 60 * 60 * 24); // Convertir a días
    }
}
