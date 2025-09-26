package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record VerifyUnlockCodeDTO(
    @Email(message = "Email inválido")
    @NotBlank(message = "Email es requerido")
    String email,
    
    @NotBlank(message = "Código es requerido")
    String code
) {
}