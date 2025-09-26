package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RequestImmediateUnlockDTO(
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email es invalido")
    String email

) {
}