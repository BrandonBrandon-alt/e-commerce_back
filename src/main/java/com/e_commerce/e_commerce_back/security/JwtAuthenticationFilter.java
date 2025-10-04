package com.e_commerce.e_commerce_back.security;

import com.e_commerce.e_commerce_back.services.implementation.JwtSessionService;
import com.e_commerce.e_commerce_back.services.implementation.JwtSessionService.SessionValidation;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final JwtSessionService jwtSessionService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();
        
        log.debug("=== JWT Filter === Procesando: {} {}", method, path);

        try {
            String token = extractTokenFromRequest(request);

            if (token != null) {
                log.debug("Token Bearer encontrado, validando...");
                
                // 1. Validar token en Redis
                SessionValidation validation = jwtSessionService.validateAccessToken(token);

                if (validation.isValid()) {
                    log.debug("Token válido en Redis");
                    
                    // 2. Extraer username del JWT
                    String username = jwtUtil.extractUsername(token);
                    log.debug("Username extraído: {}", username);

                    // 3. Verificar que no hay autenticación previa
                    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                        
                        // 4. Cargar UserDetails
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                        log.debug("UserDetails cargado para: {}", username);

                        // 5. Validar token JWT (firma, expiración, etc.)
                        if (jwtUtil.validateToken(token, userDetails)) {
                            log.debug("Token JWT válido, creando autenticación");
                            
                            // 6. Crear autenticación
                            UsernamePasswordAuthenticationToken authentication = 
                                new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                                );

                            authentication.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                            );

                            // 7. Establecer autenticación en el contexto
                            SecurityContextHolder.getContext().setAuthentication(authentication);

                            log.info("✓ Usuario autenticado: {} - SessionId: {} - Authorities: {}", 
                                username, 
                                validation.getMetadata().getSessionId(),
                                userDetails.getAuthorities());
                        } else {
                            log.warn("✗ Token JWT inválido para usuario: {}", username);
                        }
                    } else {
                        if (username == null) {
                            log.warn("Username es null en el token");
                        } else {
                            log.debug("Usuario ya autenticado previamente");
                        }
                    }
                } else {
                    log.warn("✗ Token no válido en Redis: {}", validation.getReason());
                    response.setHeader("X-Token-Invalid-Reason", validation.getReason());
                }
            } else {
                log.debug("No se encontró token Bearer en el request");
            }

        } catch (Exception e) {
            log.error("✗ Error en filtro JWT: {} - {}", e.getClass().getSimpleName(), e.getMessage());
            if (log.isDebugEnabled()) {
                log.error("Stack trace completo:", e);
            }
        }

        log.debug("=== JWT Filter === Continuando con la cadena de filtros");
        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        
        boolean skip = path.startsWith("/api/auth/login") ||
               path.startsWith("/api/auth/register") ||
               path.startsWith("/api/auth/refresh") ||
               path.startsWith("/api/auth/activate") ||
               path.startsWith("/api/auth/forgot-password") ||
               path.startsWith("/api/auth/reset-password") ||
               path.startsWith("/swagger-ui") ||
               path.startsWith("/v3/api-docs") ||
               path.startsWith("/actuator");
        
        if (skip) {
            log.debug("⊘ Saltando JWT Filter para ruta pública: {}", path);
        }
        
        return skip;
    }
}