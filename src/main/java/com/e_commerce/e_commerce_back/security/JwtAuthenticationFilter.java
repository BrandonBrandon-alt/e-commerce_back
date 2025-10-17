package com.e_commerce.e_commerce_back.security;

import com.e_commerce.e_commerce_back.services.implementation.JwtSessionService;
import com.e_commerce.e_commerce_back.services.implementation.JwtSessionService.SessionValidation;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Filtro de autenticación JWT que intercepta todas las peticiones HTTP
 * y valida los tokens de acceso en el encabezado Authorization.
 * 
 * <p>
 * Este filtro:
 * <ul>
 * <li>Extrae el token JWT del encabezado Authorization</li>
 * <li>Valida el token contra Redis y la firma JWT</li>
 * <li>Establece la autenticación en el SecurityContext si el token es
 * válido</li>
 * <li>Excluye rutas públicas que no requieren autenticación</li>
 * </ul>
 * 
 * @author E-Commerce Team
 * @version 1.0
 * @since 2025-01
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    /**
     * Rutas públicas que no requieren autenticación JWT.
     * Estas rutas serán excluidas del filtro completamente.
     * NOTA: Estas rutas deben coincidir con las definidas en SecurityConfig
     */
    private static final List<String> PUBLIC_PATH_PREFIXES = Arrays.asList(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh-token",
            "/api/auth/activate-account",
            "/api/auth/resend-activation-code",
            "/api/auth/forgot-password",
            "/api/auth/reset-password",
            "/api/auth/request-unlock",
            "/api/auth/verify-unlock-code",
            "/api/auth/resend-reset-code",
            "/swagger-ui",
            "/v3/api-docs",
            "/swagger-resources",
            "/webjars",
            "/actuator/health",
            "/actuator/info");

    private static final String ERROR_PATH = "/error";

    private final JwtUtil jwtUtil;
    private final JwtSessionService jwtSessionService;
    private final UserDetailsService userDetailsService;

    /**
     * Procesa cada petición HTTP para validar el token JWT y establecer la
     * autenticación.
     *
     * @param request     la petición HTTP
     * @param response    la respuesta HTTP
     * @param filterChain la cadena de filtros
     * @throws ServletException si ocurre un error en el servlet
     * @throws IOException      si ocurre un error de I/O
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        if (log.isDebugEnabled()) {
            log.debug("Processing request: {} {}", request.getMethod(), request.getRequestURI());
        }

        try {
            String token = extractTokenFromRequest(request);

            if (StringUtils.hasText(token)) {
                authenticateWithToken(token, request);
            } else {
                log.debug("No Bearer token found in Authorization header");
            }

        } catch (Exception e) {
            log.error("Authentication error: {} - {}", e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Full stack trace:", e);
            }
            // No relanzamos la excepción para permitir que Spring Security maneje el error
            // apropiadamente
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Autentica al usuario usando el token JWT proporcionado.
     *
     * @param token   el token JWT
     * @param request la petición HTTP para detalles adicionales
     */
    private void authenticateWithToken(String token, HttpServletRequest request) {
        log.debug("Validating Bearer token");

        SessionValidation validation = jwtSessionService.validateAccessToken(token);

        if (!validation.isValid()) {
            log.warn("Invalid token in Redis: {}", validation.getReason());
            return;
        }

        log.debug("Token valid in Redis");

        String username = jwtUtil.extractUsername(token);

        if (!StringUtils.hasText(username)) {
            log.warn("Username is null or empty in token");
            return;
        }

        log.debug("Username extracted: {}", username);

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            log.debug("User already authenticated in this request");
            return;
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        log.debug("UserDetails loaded for: {}", username);

        if (!jwtUtil.validateToken(token, userDetails)) {
            log.warn("Invalid JWT token for user: {}", username);
            return;
        }

        log.debug("JWT token valid, establishing authentication");

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        log.info("User authenticated successfully: {} - SessionId: {} - Authorities: {}",
                username,
                validation.getMetadata().getSessionId(),
                userDetails.getAuthorities());
    }

    /**
     * Extrae el token JWT del encabezado Authorization.
     *
     * @param request la petición HTTP
     * @return el token JWT sin el prefijo "Bearer ", o null si no existe
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX_LENGTH);
        }

        return null;
    }

    /**
     * Determina si este filtro debe ser omitido para la petición actual.
     * Se omite para rutas públicas que no requieren autenticación.
     *
     * @param request la petición HTTP
     * @return true si el filtro debe ser omitido, false en caso contrario
     */
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();

        // Verificar rutas públicas por prefijo
        boolean isPublicPath = PUBLIC_PATH_PREFIXES.stream()
                .anyMatch(path::startsWith);

        // Verificar ruta de error exacta
        boolean isErrorPath = ERROR_PATH.equals(path);

        boolean shouldSkip = isPublicPath || isErrorPath;

        if (shouldSkip && log.isDebugEnabled()) {
            log.debug("Skipping JWT filter for public path: {}", path);
        }

        return shouldSkip;
    }
}