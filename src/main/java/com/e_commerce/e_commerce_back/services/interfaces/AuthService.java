package com.e_commerce.e_commerce_back.services.interfaces;

import com.e_commerce.e_commerce_back.dto.*;

/**
 * Interfaz para servicios de autenticación
 */
public interface AuthService {
    
    /**
     * Autentica un usuario y genera un token JWT
     * @param loginDTO Datos de login
     * @return Respuesta con token y información del usuario
     */
    AuthResponseDTO login(LoginDTO loginDTO);
    
    /**
     * Registra un nuevo usuario
     * @param createUserDTO Datos del usuario a registrar
     * @return Respuesta de registro
     */
    AuthResponseDTO register(RegisterUserDTO createUserDTO);
    
    /**
     * Valida un token JWT
     * @param authHeader Header de autorización con el token
     * @return Información de validación del token
     */
    TokenValidationDTO validateToken(String authHeader);
    
    /**
     * Obtiene información del usuario autenticado actual
     * @return Información del usuario
     */
    UserInfoDTO getCurrentUserInfo();
    
    /**
     * Cierra sesión invalidando el token
     * @param authHeader Header de autorización con el token
     */
    void logout(String authHeader);
    
    /**
     * Activa una cuenta de usuario usando el código de activación
     * @param activateAccountDTO Datos de activación
     * @return Respuesta de activación
     */
    AuthResponseDTO activateAccount(ActivateAccountDTO activateAccountDTO);
    
    /**
     * Reenvía el código de activación a un usuario
     * @param activateAccountDTO Datos de activación
     * @return Respuesta de reenvío
     */
    AuthResponseDTO resendActivationCode(String email);
}
