package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;


public record ActivateAccountDTO(
    
    @NotBlank(message = "El email es requerido")
    @Email(message = "El email debe tener un formato válido")
    @Size(max = 100, message = "El email no puede exceder 100 caracteres")
    String email,
    
    @NotBlank(message = "El código de activación es requerido")
    @Pattern(regexp = "^[0-9]{6}$", message = "El código de activación debe ser de 6 dígitos")
    String activationCode
) {
}
