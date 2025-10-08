package com.e_commerce.e_commerce_back.config;

import com.e_commerce.e_commerce_back.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configurando SecurityFilterChain");
        
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .authorizeHttpRequests(auth -> auth
                // Rutas públicas de autenticación
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/register",
                    "/api/auth/refresh-token",
                    "/api/auth/activate-account",
                    "/api/auth/resend-activation-code",
                    "/api/auth/forgot-password",
                    "/api/auth/reset-password",
                    "/api/auth/request-unlock",
                    "/api/auth/verify-unlock-code"
                ).permitAll()
                // Documentación API (Swagger)
                .requestMatchers(
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/v3/api-docs/**",
                    "/swagger-resources/**",
                    "/webjars/**"
                ).permitAll()
                // Actuator endpoints públicos
                .requestMatchers(
                    "/actuator/health",
                    "/actuator/info"
                ).permitAll()
                // Endpoint de error
                .requestMatchers("/error").permitAll()
                // Todas las demás rutas requieren autenticación
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        log.info("SecurityFilterChain configurado exitosamente");
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Orígenes permitidos
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:3000",
            "http://localhost:4200",
            "http://localhost:5173"
        ));
        
        // Métodos HTTP permitidos
        configuration.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));
        
        // Headers permitidos - especificar explícitamente para mejor seguridad
        configuration.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "Content-Type",
            "Accept",
            "X-Requested-With",
            "X-XSRF-TOKEN"
        ));
        
        // Headers expuestos al cliente
        configuration.setExposedHeaders(Arrays.asList(
            "Authorization",
            "X-Token-Invalid-Reason"
        ));
        
        // Permitir credenciales (cookies, authorization headers)
        configuration.setAllowCredentials(true);
        
        // Tiempo de caché de la configuración CORS (1 hora)
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        log.info("CORS configurado con orígenes: {}", configuration.getAllowedOrigins());
        return source;
    }
}