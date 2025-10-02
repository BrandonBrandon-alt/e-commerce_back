package com.e_commerce.e_commerce_back.services.interfaces;

import com.e_commerce.e_commerce_back.entity.User;

/**
 * Servicio para el envío de emails
 */
public interface EmailService {

    /**
     * Genera un código de verificación de 6 dígitos.
     * @return El código generado como String.
     */
    String generateActivationCode();
    
    /**
     * Genera un código de verificación de 6 dígitos.
     * @return El código generado como String.
     */
    String generateResetCode();
    
    /**
     * Envía un email de activación de cuenta con código de verificación
     * @param user Usuario al que se enviará el email
     * @param activationCode Código de activación generado
     */
    void sendActivationEmail(User user, String activationCode);
    
    /**
     * Envía un email de restablecimiento de contraseña
     * @param user Usuario al que se enviará el email
     * @param resetCode Código de restablecimiento generado
     */
    void sendPasswordResetEmail(User user, String resetCode);
    
    /**
     * Envía un email de bienvenida después de la activación exitosa
     * @param user Usuario que activó su cuenta
     */
    void sendWelcomeEmail(User user);
    
    /**
     * Envía un email de notificacion de cambio de contraseña
     * @param user Usuario que cambió su contraseña
     */
    void sendPasswordChangedNotification(User user);

    /**
     * Envía un email de solicitud de desbloqueo inmediato
     * @param user Usuario al que se enviará el email
     */
    void sendUnlockCode(User user, String unlockCode);


    /**
     * Envía código de verificación al nuevo email después de cambio
     */
    void sendEmailChangeVerification(User user, String verificationCode);
    
    /**
     * Notifica al email anterior que se cambió el email
     */
    void sendEmailChangedNotification(String oldEmail, String newEmail);
    
    /**
     * Notifica confirmación de cambio de contraseña
     */
    void sendPasswordChangedConfirmationEmail(User user);
    
    /**
     * Notifica que la cuenta fue desbloqueada
     */
    void sendAccountUnlockedEmail(User user);


    
}
