package com.e_commerce.e_commerce_back.security;

import com.e_commerce.e_commerce_back.entity.User;
import com.e_commerce.e_commerce_back.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Collections;

/**
 * Servicio personalizado para cargar detalles del usuario
 * Implementa UserDetailsService de Spring Security
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.debug("Cargando usuario por email: {}", email);
        
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("Usuario no encontrado con email: {}", email);
                    return new UsernameNotFoundException("Usuario no encontrado con email: " + email);
                });

        log.debug("Usuario encontrado: {}, habilitado: {}", user.getEmail(), user.isEnabled());
        
        return createUserPrincipal(user);
    }

    /**
     * Crea el UserDetails a partir de la entidad User
     */
    private UserDetails createUserPrincipal(User user) {
        Collection<GrantedAuthority> authorities = getAuthorities(user);
        
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPassword())
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(!user.isEnabled())
                .build();
    }

    /**
     * Obtiene las autoridades del usuario basadas en su rol
     */
    private Collection<GrantedAuthority> getAuthorities(User user) {
        String roleName = "ROLE_" + user.getRole();
        log.debug("Asignando rol: {} al usuario: {}", roleName, user.getEmail());
        return Collections.singletonList(new SimpleGrantedAuthority(roleName));
    }

    /**
     * Carga usuario por ID (útil para operaciones internas)
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(Long userId) {
        log.debug("Cargando usuario por ID: {}", userId);
        
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("Usuario no encontrado con ID: {}", userId);
                    return new UsernameNotFoundException("Usuario no encontrado con ID: " + userId);
                });

        return createUserPrincipal(user);
    }
}
