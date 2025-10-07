package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * DTO para solicitar cambio de email (Paso 1)
 * Envía código de verificación al nuevo email
 */
public record RequestEmailChangeDTO(
        @NotBlank(message = "user.validation.email.required")
        @Email(message = "user.validation.email.format")
        @Size(max = 100, message = "user.validation.email.size")
        String newEmail,

        @NotBlank(message = "user.validation.emailConfirmation.required")
        @Email(message = "user.validation.emailConfirmation.format")
        @Size(max = 100, message = "user.validation.emailConfirmation.size")
        String newEmailConfirmation,

        @NotBlank(message = "user.validation.currentPassword.required")
        String currentPassword) {

    /**
     * Valida que los emails coincidan
     */
    public boolean emailsMatch() {
        return newEmail != null && newEmail.equals(newEmailConfirmation);
    }
}
