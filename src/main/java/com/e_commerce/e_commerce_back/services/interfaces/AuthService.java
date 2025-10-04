package com.e_commerce.e_commerce_back.services.interfaces;

import com.e_commerce.e_commerce_back.dto.*;

/**
 * Interfaz para servicios de autenticación
 */
public interface AuthService {
     // --- Autenticación Principal ---
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
     * Cierra sesión invalidando el token
     * @param authHeader Header de autorización con el token
     */
    void logout(String authHeader);
    
      //-------------------GESTION DE TOKENS-------------------//
    /**
     * Valida un token JWT
     * @param authHeader Header de autorización con el token
     * @return Información de validación del token
     */
    TokenValidationDTO validateToken(String authHeader);
    
    //-------------------GESTION DEL USUARIO AUTHENTICADO-------------------//
    /**
     * Obtiene información del usuario autenticado actual
     * @return Información del usuario
     */
    UserInfoDTO getCurrentUserInfo();

    /**
     * Obtiene información del usuario autenticado actual
     * @return Información del usuario
     */
    AuthResponseDTO refreshToken(RefreshTokenDTO refreshTokenDTO);
    
    /**
     * Cambia la contraseña del usuario autenticado actual
     * @param changePasswordDTO Datos de cambio de contraseña
     */
    AuthResponseDTO changePassword(ChangePasswordDTO changePasswordDTO);
    

    /**
     * Cambia el email del usuario autenticado actual
     * @param changeEmailDTO Datos de cambio de email
     */
    AuthResponseDTO changeEmail(ChangeEmailDTO changeEmailDTO);


    /**
     * Actualiza la información del usuario autenticado actual
     * @param userInfoDTO Datos de la información del usuario
     */
    AuthResponseDTO updateUserInfo(UpdateUserProfileDTO updateUserInfoDTO);
    
    //-------------------GESTION DE LA CUENTA-------------------//
    
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

    //-------------------GESTION DE LA CONTRASEÑA-------------------//
    /**
     * Inicia el proceso de reseteo de contraseña para un usuario.
     * Genera un código de reseteo y lo envía por email.
     * @param email El email del usuario que solicita el reseteo.
     * @return Una respuesta indicando si el email fue enviado.
     */
    AuthResponseDTO forgotPassword(ForgotPasswordDTO forgotPasswordDTO);

    /**
     * Resetea la contraseña de un usuario
     * @param resetPasswordDTO Datos de reseteo de contraseña
     * @return Respuesta de reseteo
     */
    AuthResponseDTO resetPassword(ResetPasswordDTO resetPasswordDTO);

    //-------------------GESTION DE LA CUENTA-------------------//

    /**
     * Solicita un desbloqueo inmediato para un usuario
     * @param requestImmediateUnlockDTO Datos de solicitud de desbloqueo
     * @return Respuesta de solicitud de desbloqueo
     */
    
    AuthResponseDTO requestImmediateUnlock(RequestImmediateUnlockDTO requestImmediateUnlockDTO);

    /**
     * Desbloquea una cuenta de usuario
     * @param requestImmediateUnlockDTO Datos de desbloqueo
     * @return Respuesta de desbloqueo
     */
    AuthResponseDTO verifyUnlockCode(VerifyUnlockCodeDTO verifyUnlockCodeDTO);
}
