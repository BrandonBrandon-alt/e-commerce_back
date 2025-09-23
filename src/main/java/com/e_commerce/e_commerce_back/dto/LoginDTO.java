package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record LoginDTO(
        @NotBlank(message = "El email es obligatorio") @Email(message = "El formato del email no es válido") String email,
        @NotBlank(message = "La contraseña es obligatoria") @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres") @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", message = "La contraseña debe contener al menos: 1 número, 1 minúscula, 1 mayúscula y 1 carácter especial") String password) {
}