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
                        htmlContent
                    );
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
                        htmlContent
                    );
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
                        htmlContent
                    );
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
                DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")
            ));
            context.setVariable("currentYear", LocalDateTime.now().getYear());
            
            String htmlContent = templateEngine.process("emails/password-changed-email", context);
            
            // Envío asíncrono
            CompletableFuture.runAsync(() -> {
                try {
                    sendHtmlEmail(
                        user.getEmail(),
                        "Contraseña cambiada - " + fromName,
                        htmlContent
                    );
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
     * @throws UnsupportedEncodingException 
     */
    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setFrom(fromAddress, fromName);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        
        mailSender.send(message);
    }

    /**
     * Método utilitario para generar códigos de activación/reset
     */
    public static String generateVerificationCode() {
        return String.format("%06d", (int) (Math.random() * 1000000));
    }
}
