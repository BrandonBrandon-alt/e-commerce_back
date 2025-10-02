package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record VerifyUnlockCodeDTO(
    @NotBlank(message = "Código es requerido")
    @Size(min = 6, max = 6, message = "Código debe tener 6 caracteres")
    String code
) {
}