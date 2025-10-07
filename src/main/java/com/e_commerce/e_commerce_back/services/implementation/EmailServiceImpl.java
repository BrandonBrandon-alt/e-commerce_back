package com.e_commerce.e_commerce_back.services.implementation;

import com.e_commerce.e_commerce_back.entity.User;
import com.e_commerce.e_commerce_back.services.interfaces.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CompletableFuture;

/**
 * Implementación del servicio de email
 * Maneja el envío de emails usando plantillas Thymeleaf
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${app.email.from-name}")
    private String fromName;

    @Value("${app.email.from-address}")
    private String fromAddress;

    @Value("${app.email.activation-code-expiry-minutes}")
    private Integer activationCodeExpiryMinutes;

    @Value("${app.email.reset-password-code-expiry-minutes}")
    private Integer resetPasswordCodeExpiryMinutes;

    @Override
    public void sendActivationEmail(User user, String activationCode) {
        log.info("Enviando email de activación a: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("userName", user.getFullName());
            context.setVariable("activationCode", activationCode);
            context.setVariable("expiryMinutes", activationCodeExpiryMinutes);
            context.setVariable("currentYear", LocalDateTime.now().getYear());

            String htmlContent = templateEngine.process("emails/activation-email", context);

            // Envío asíncrono para no bloquear el registro
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            user.getEmail(),
                            "Activa tu cuenta - " + fromName,
                            htmlContent);
                    log.info("Email de activación enviado exitosamente a: {}", user.getEmail());
                } catch (Exception e) {
                    log.error("Error enviando email de activación a {}: {}", user.getEmail(), e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando email de activación para {}: {}", user.getEmail(), e.getMessage());
            throw new RuntimeException("Error enviando email de activación", e);
        }
    }

    @Override
    public void sendPasswordResetEmail(User user, String resetCode) {
        log.info("Enviando email de restablecimiento de contraseña a: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("userName", user.getFullName());
            context.setVariable("resetCode", resetCode);
            context.setVariable("expiryMinutes", resetPasswordCodeExpiryMinutes);
            context.setVariable("currentYear", LocalDateTime.now().getYear());

            String htmlContent = templateEngine.process("emails/password-reset-email", context);

            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            user.getEmail(),
                            "Restablece tu contraseña - " + fromName,
                            htmlContent);
                    log.info("Email de restablecimiento enviado exitosamente a: {}", user.getEmail());
                } catch (Exception e) {
                    log.error("Error enviando email de restablecimiento a {}: {}", user.getEmail(), e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando email de restablecimiento para {}: {}", user.getEmail(), e.getMessage());
            throw new RuntimeException("Error enviando email de restablecimiento", e);
        }
    }

    @Override
    public void sendWelcomeEmail(User user) {
        log.info("Enviando email de bienvenida a: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("userName", user.getFullName());
            context.setVariable("userEmail", user.getEmail());
            context.setVariable("currentYear", LocalDateTime.now().getYear());

            String htmlContent = templateEngine.process("emails/welcome-email", context);

            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            user.getEmail(),
                            "¡Bienvenido a " + fromName + "!",
                            htmlContent);
                    log.info("Email de bienvenida enviado exitosamente a: {}", user.getEmail());
                } catch (Exception e) {
                    log.error("Error enviando email de bienvenida a {}: {}", user.getEmail(), e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando email de bienvenida para {}: {}", user.getEmail(), e.getMessage());
        }
    }

    @Override
    public void sendPasswordChangedNotification(User user) {
        log.info("Enviando notificación de cambio de contraseña a: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("userName", user.getFullName());
            context.setVariable("changeDateTime", LocalDateTime.now().format(
                    DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));
            context.setVariable("currentYear", LocalDateTime.now().getYear());

            String htmlContent = templateEngine.process("emails/password-changed-email", context);

            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            user.getEmail(),
                            "Contraseña cambiada - " + fromName,
                            htmlContent);
                    log.info("Notificación de cambio de contraseña enviada a: {}", user.getEmail());
                } catch (Exception e) {
                    log.error("Error enviando notificación de cambio de contraseña a {}: {}",
                            user.getEmail(), e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando notificación de cambio de contraseña para {}: {}",
                    user.getEmail(), e.getMessage());
        }
    }

    /**
     * Método privado para enviar emails HTML
     * 
     * @throws UnsupportedEncodingException
     */
    private void sendHtmlEmail(String to, String subject, String htmlContent)
            throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(fromAddress, fromName);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }

    @Override
    public String generateActivationCode() {
        return String.format("%06d", (int) (Math.random() * 1000000));
    }

    @Override
    public String generateResetCode() {
        return String.format("%06d", (int) (Math.random() * 1000000));
    }

    @Override
    public void sendUnlockCode(User user, String unlockCode) {
        log.info("Enviando email con código de desbloqueo a: {}", user.getEmail());

        try {
            Context context = new Context();
            context.setVariable("userName", user.getFullName());
            context.setVariable("unlockCode", unlockCode);
            context.setVariable("expiryMinutes", activationCodeExpiryMinutes); // Reutilizamos el tiempo de expiración
            context.setVariable("currentYear", LocalDateTime.now().getYear());
            context.setVariable("requestDateTime", LocalDateTime.now().format(
                    DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")));

            String htmlContent = templateEngine.process("emails/unlock-code-email", context);

            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            user.getEmail(),
                            "Código de desbloqueo de cuenta - " + fromName,
                            htmlContent);
                    log.info("Email con código de desbloqueo enviado exitosamente a: {}", user.getEmail());
                } catch (Exception e) {
                    log.error("Error enviando email de código de desbloqueo a {}: {}", user.getEmail(), e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando email de código de desbloqueo para {}: {}", user.getEmail(), e.getMessage());
            throw new RuntimeException("Error enviando email de código de desbloqueo", e);
        }
    }

    @Override
    public void sendEmailChangeVerification(User user, String verificationCode) {
        log.info("Enviando código de verificación de cambio de email a: {}", user.getEmail());

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromAddress);
            helper.setTo(user.getEmail()); // El NUEVO email
            helper.setSubject("Verifica tu nuevo correo electrónico - " + fromName);

            String htmlContent = buildEmailChangeVerificationTemplate(user, verificationCode);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Email de verificación de cambio enviado exitosamente a: {}", user.getEmail());

        } catch (MessagingException e) {
            log.error("Error enviando email de verificación de cambio: {}", e.getMessage());
            throw new RuntimeException("Error enviando email de verificación", e);
        }
    }

    @Override
    public void sendEmailChangedNotification(String oldEmail, String newEmail) {
        log.info("Enviando notificación de cambio de email a: {}", oldEmail);

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromAddress);
            helper.setTo(oldEmail); // El email ANTERIOR
            helper.setSubject("Tu correo electrónico ha sido cambiado - " + fromName);

            String htmlContent = buildEmailChangedNotificationTemplate(oldEmail, newEmail);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Notificación de cambio de email enviada a: {}", oldEmail);

        } catch (MessagingException e) {
            log.error("Error enviando notificación de cambio de email: {}", e.getMessage());
            // No lanzar excepción porque es solo una notificación
        }
    }

    @Override
    public void sendPasswordChangedConfirmationEmail(User user) {
        log.info("Enviando confirmación de cambio de contraseña a: {}", user.getEmail());

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromAddress);
            helper.setTo(user.getEmail());
            helper.setSubject("Contraseña cambiada exitosamente - " + fromName);

            String htmlContent = buildPasswordChangedTemplate(user);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Email de confirmación de cambio de contraseña enviado a: {}", user.getEmail());

        } catch (MessagingException e) {
            log.error("Error enviando confirmación de cambio de contraseña: {}", e.getMessage());
        }
    }

    @Override
    public void sendAccountUnlockedEmail(User user) {
        log.info("Enviando confirmación de desbloqueo a: {}", user.getEmail());

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromAddress);
            helper.setTo(user.getEmail());
            helper.setSubject("Cuenta desbloqueada - " + fromName);

            String htmlContent = buildAccountUnlockedTemplate(user);
            helper.setText(htmlContent, true);

            mailSender.send(message);
            log.info("Email de confirmación de desbloqueo enviado a: {}", user.getEmail());

        } catch (MessagingException e) {
            log.error("Error enviando confirmación de desbloqueo: {}", e.getMessage());
        }
    }

    private String buildEmailChangeVerificationTemplate(User user, String verificationCode) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #4CAF50; color: white; padding: 20px; text-align: center; }
                        .content { background: #f9f9f9; padding: 30px; }
                        .code-box { background: #fff; border: 2px solid #4CAF50; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; margin: 20px 0; letter-spacing: 5px; }
                        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Verifica tu nuevo correo electrónico</h1>
                        </div>
                        <div class="content">
                            <p>Hola <strong>%s</strong>,</p>
                            <p>Has cambiado tu correo electrónico. Para completar el cambio, verifica tu nuevo correo ingresando el siguiente código:</p>
                            <div class="code-box">%s</div>
                            <p>Este código expirará en <strong>15 minutos</strong>.</p>
                            <div class="warning">
                                <strong>⚠️ Atención:</strong> Si no solicitaste este cambio, ignora este correo y tu email anterior seguirá activo.
                            </div>
                        </div>
                        <div class="footer">
                            <p>Este es un correo automático, por favor no respondas.</p>
                            <p>&copy; %s - Todos los derechos reservados</p>
                        </div>
                    </div>
                </body>
                </html>
                """
                .formatted(user.getFullName(), verificationCode, fromName);
    }

    private String buildEmailChangedNotificationTemplate(String oldEmail, String newEmail) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #ff9800; color: white; padding: 20px; text-align: center; }
                        .content { background: #f9f9f9; padding: 30px; }
                        .alert { background: #f44336; color: white; padding: 15px; margin: 20px 0; border-radius: 5px; }
                        .info { background: #e3f2fd; border-left: 4px solid #2196F3; padding: 15px; margin: 20px 0; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>⚠️ Cambio de correo electrónico</h1>
                        </div>
                        <div class="content">
                            <p>Hola,</p>
                            <p>Te informamos que el correo electrónico asociado a tu cuenta ha sido cambiado.</p>
                            <div class="info">
                                <p><strong>Email anterior:</strong> %s</p>
                                <p><strong>Nuevo email:</strong> %s</p>
                                <p><strong>Fecha:</strong> %s</p>
                            </div>
                            <div class="alert">
                                <strong>🚨 ¿No fuiste tú?</strong><br>
                                Si NO autorizaste este cambio, tu cuenta puede estar comprometida.
                                Contacta inmediatamente a soporte.
                            </div>
                            <p>A partir de ahora, todas las comunicaciones se enviarán al nuevo correo.</p>
                        </div>
                        <div class="footer">
                            <p>Este es un correo automático, por favor no respondas.</p>
                            <p>&copy; %s - Todos los derechos reservados</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(oldEmail, newEmail,
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")), fromName);
    }

    private String buildPasswordChangedTemplate(User user) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #4CAF50; color: white; padding: 20px; text-align: center; }
                        .content { background: #f9f9f9; padding: 30px; }
                        .alert { background: #f44336; color: white; padding: 15px; margin: 20px 0; border-radius: 5px; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>✓ Contraseña cambiada</h1>
                        </div>
                        <div class="content">
                            <p>Hola <strong>%s</strong>,</p>
                            <p>Tu contraseña ha sido cambiada exitosamente.</p>
                            <p><strong>Fecha del cambio:</strong> %s</p>
                            <div class="alert">
                                <strong>🚨 ¿No fuiste tú?</strong><br>
                                Si NO cambiaste tu contraseña, tu cuenta puede estar comprometida.
                                Restablece tu contraseña inmediatamente.
                            </div>
                        </div>
                        <div class="footer">
                            <p>Este es un correo automático, por favor no respondas.</p>
                            <p>&copy; %s - Todos los derechos reservados</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(user.getFullName(),
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")), fromName);
    }

    private String buildAccountUnlockedTemplate(User user) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #4CAF50; color: white; padding: 20px; text-align: center; }
                        .content { background: #f9f9f9; padding: 30px; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>✓ Cuenta desbloqueada</h1>
                        </div>
                        <div class="content">
                            <p>Hola <strong>%s</strong>,</p>
                            <p>Tu cuenta ha sido desbloqueada exitosamente.</p>
                            <p>Ya puedes iniciar sesión normalmente.</p>
                            <p><strong>Fecha de desbloqueo:</strong> %s</p>
                        </div>
                        <div class="footer">
                            <p>Este es un correo automático, por favor no respondas.</p>
                            <p>&copy; %s - Todos los derechos reservados</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(user.getFullName(),
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")), fromName);
    }

    @Override
    public void sendEmailChangeVerificationCode(String newEmail, String userName, String verificationCode) {
        log.info("Enviando código de verificación de cambio de email a: {}", newEmail);

        try {
            String htmlContent = buildEmailChangeVerificationTemplate(newEmail, userName, verificationCode);

            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            newEmail,
                            "Verifica tu nuevo email - " + fromName,
                            htmlContent);
                    log.info("Código de verificación de cambio de email enviado exitosamente a: {}", newEmail);
                } catch (Exception e) {
                    log.error("Error enviando código de verificación a {}: {}", newEmail, e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando email de verificación para {}: {}", newEmail, e.getMessage());
            throw new RuntimeException("Error enviando código de verificación", e);
        }
    }

    @Override
    public void sendEmailChangeRequestNotification(String currentEmail, String newEmail) {
        log.info("Enviando notificación de solicitud de cambio de email a: {}", currentEmail);

        try {
            String htmlContent = buildEmailChangeRequestTemplate(currentEmail, newEmail);

            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                            currentEmail,
                            "Solicitud de cambio de email - " + fromName,
                            htmlContent);
                    log.info("Notificación de solicitud enviada exitosamente a: {}", currentEmail);
                } catch (Exception e) {
                    log.error("Error enviando notificación a {}: {}", currentEmail, e.getMessage());
                }
            });

        } catch (Exception e) {
            log.error("Error preparando notificación para {}: {}", currentEmail, e.getMessage());
            throw new RuntimeException("Error enviando notificación", e);
        }
    }

    private String buildEmailChangeVerificationTemplate(String newEmail, String userName, String verificationCode) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #2196F3; color: white; padding: 20px; text-align: center; }
                        .content { background: #f9f9f9; padding: 30px; }
                        .code-box { background: #fff; border: 2px dashed #2196F3; padding: 20px; text-align: center; margin: 20px 0; }
                        .code { font-size: 32px; font-weight: bold; color: #2196F3; letter-spacing: 5px; }
                        .warning { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔐 Verifica tu nuevo email</h1>
                        </div>
                        <div class="content">
                            <p>Hola <strong>%s</strong>,</p>
                            <p>Has solicitado cambiar tu email a: <strong>%s</strong></p>
                            <p>Para confirmar este cambio, ingresa el siguiente código de verificación:</p>
                            <div class="code-box">
                                <div class="code">%s</div>
                            </div>
                            <p><strong>Este código expira en %d minutos.</strong></p>
                            <div class="warning">
                                <strong>⚠️ Importante:</strong> Si no solicitaste este cambio, ignora este email. 
                                Tu email actual permanecerá sin cambios.
                            </div>
                        </div>
                        <div class="footer">
                            <p>Este es un correo automático, por favor no respondas.</p>
                            <p>&copy; %s - Todos los derechos reservados</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(userName, newEmail, verificationCode, activationCodeExpiryMinutes, fromName);
    }

    private String buildEmailChangeRequestTemplate(String currentEmail, String newEmail) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .header { background: #FF9800; color: white; padding: 20px; text-align: center; }
                        .content { background: #f9f9f9; padding: 30px; }
                        .alert { background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0; }
                        .info-box { background: #e3f2fd; padding: 15px; margin: 20px 0; border-radius: 5px; }
                        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>⚠️ Solicitud de cambio de email</h1>
                        </div>
                        <div class="content">
                            <p>Hola,</p>
                            <p>Se ha solicitado cambiar el email de tu cuenta.</p>
                            <div class="info-box">
                                <p><strong>Email actual:</strong> %s</p>
                                <p><strong>Nuevo email solicitado:</strong> %s</p>
                                <p><strong>Fecha:</strong> %s</p>
                            </div>
                            <div class="alert">
                                <strong>⚠️ Importante:</strong>
                                <ul>
                                    <li>Se ha enviado un código de verificación al nuevo email</li>
                                    <li>Tu email actual NO cambiará hasta que se verifique el código</li>
                                    <li>Si no fuiste tú, tu cuenta está segura - el cambio no se completará</li>
                                    <li>El código expira en %d minutos</li>
                                </ul>
                            </div>
                            <p>Si no solicitaste este cambio, puedes ignorar este mensaje. Tu email permanecerá sin cambios.</p>
                        </div>
                        <div class="footer">
                            <p>Este es un correo automático, por favor no respondas.</p>
                            <p>&copy; %s - Todos los derechos reservados</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(currentEmail, newEmail, 
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")),
                activationCodeExpiryMinutes, fromName);
    }

}
