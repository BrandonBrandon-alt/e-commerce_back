package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * DTO para verificar y confirmar cambio de email (Paso 2)
 * Verifica el código enviado al nuevo email
 */
public record VerifyEmailChangeDTO(
        @NotBlank(message = "user.validation.verificationCode.required")
        @Size(min = 6, max = 6, message = "user.validation.verificationCode.size")
        @Pattern(regexp = "^[0-9]{6}$", message = "user.validation.verificationCode.format")
        String verificationCode) {
}
