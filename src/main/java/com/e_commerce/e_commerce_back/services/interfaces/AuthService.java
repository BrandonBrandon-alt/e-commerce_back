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
     * Autentica un usuario con Google OAuth2
     * @param googleOAuthLoginDTO Token de ID de Google
     * @return Respuesta con token y información del usuario
     */
    AuthResponseDTO loginWithGoogle(GoogleOAuthLoginDTO googleOAuthLoginDTO);

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
     * @deprecated Usar requestEmailChange() y verifyEmailChange() en su lugar
     * Cambia el email del usuario autenticado actual (INSEGURO - cambia sin verificar acceso al nuevo email)
     * @param changeEmailDTO Datos de cambio de email
     */
    @Deprecated
    AuthResponseDTO changeEmail(ChangeEmailDTO changeEmailDTO);

    /**
     * Paso 1: Solicita cambio de email y envía código de verificación al NUEVO email
     * Esto garantiza que el usuario tenga acceso al nuevo email antes de cambiar
     * @param requestEmailChangeDTO Datos de solicitud de cambio de email
     * @return Respuesta indicando que el código fue enviado
     */
    AuthResponseDTO requestEmailChange(RequestEmailChangeDTO requestEmailChangeDTO);

    /**
     * Paso 2: Verifica el código y confirma el cambio de email
     * Solo cambia el email si el código es válido
     * @param verifyEmailChangeDTO Código de verificación
     * @return Respuesta de confirmación de cambio
     */
    AuthResponseDTO verifyEmailChange(VerifyEmailChangeDTO verifyEmailChangeDTO);


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

    /**
     * Reenvía el código de reseteo a un usuario
     * @param resendresetCodeDTO Datos de reenvío de código de reseteo
     * @return Respuesta de reenvío
     */
    AuthResponseDTO resendResetCode(ResendresetCodeDTO resendresetCodeDTO);

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
