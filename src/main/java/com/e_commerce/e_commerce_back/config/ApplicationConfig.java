package com.e_commerce.e_commerce_back.config;

import com.e_commerce.e_commerce_back.repository.UserRepository;    
import lombok.RequiredArgsConstructor;  
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class ApplicationConfig {

    private final com.e_commerce.e_commerce_back.repository.UserRepository userRepository;

    /**
     * UserDetailsService personalizado que carga usuarios desde la base de datos
     */
    @Bean
    public UserDetailsService userDetailsService() {
        log.info("Configurando UserDetailsService personalizado");
        return username -> {
            log.debug("Buscando usuario: {}", username);
            return userRepository.findByEmail(username)
                    .orElseThrow(() -> {
                        log.warn("Usuario no encontrado: {}", username);
                        return new UsernameNotFoundException("Usuario no encontrado: " + username);
                    });
        };
    }

    /**
     * AuthenticationProvider que usa nuestro UserDetailsService y PasswordEncoder
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        log.info("Configurando DaoAuthenticationProvider");
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        log.info("DaoAuthenticationProvider configurado exitosamente");
        return authProvider;
    }

    /**
     * AuthenticationManager para manejar la autenticación
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        log.info("Configurando AuthenticationManager");
        return config.getAuthenticationManager();
    }

    /**
     * PasswordEncoder usando BCrypt para hash de contraseñas
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        log.info("Configurando BCryptPasswordEncoder");
        return new BCryptPasswordEncoder();
    }
}