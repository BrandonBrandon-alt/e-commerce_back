package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record ActivateAccountDTO(
    
    @NotBlank(message = "El código de activación es requerido")
    @Pattern(regexp = "^[0-9]{6}$", message = "El código de activación debe ser de 6 dígitos")
    String activationCode
) {
}
