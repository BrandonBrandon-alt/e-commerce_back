package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record CreateUserDTO(
        @NotBlank(message = "El número de identificación es obligatorio") @Size(min = 8, max = 100, message = "El número de identificación debe tener entre 8 y 100 caracteres") String idNumber,
        @NotBlank(message = "El nombre es obligatorio") @Size(min = 2, max = 50, message = "El nombre debe tener entre 2 y 50 caracteres") String name,
        @NotBlank(message = "El apellido es obligatorio") @Size(min = 2, max = 50, message = "El apellido debe tener entre 2 y 50 caracteres") String lastName,
        @NotBlank(message = "El email es obligatorio") @Email(message = "El email debe tener un formato válido") String email,
        @NotBlank(message = "El número de teléfono es obligatorio") @Size(min = 10, max = 15, message = "El número de teléfono debe tener entre 10 y 15 caracteres") String phoneNumber,
        @NotBlank(message = "La contraseña es obligatoria") @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres") @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", message = "La contraseña debe contener al menos: 1 número, 1 minúscula, 1 mayúscula y 1 carácter especial") String password,
        @NotBlank(message = "El rol es obligatorio") String role) {
}   