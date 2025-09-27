package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyUnlockCodeDTO(
    @NotBlank(message = "Código es requerido")
    String code
) {
}