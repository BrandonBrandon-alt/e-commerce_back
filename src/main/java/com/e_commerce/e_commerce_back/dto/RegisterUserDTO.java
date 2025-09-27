package com.e_commerce.e_commerce_back.dto;

import java.time.LocalDate;

import jakarta.validation.constraints.*;


public record RegisterUserDTO(
        @NotBlank(message = "user.validation.idNumber.required")
        @Size(min = 2, max = 15, message = "user.validation.idNumber.size") // Consistente con entidad
        @Pattern(regexp = "^[0-9A-Za-z-]+$", message = "user.validation.idNumber.format") // Mismo patrón que entidad
        String idNumber,
        
        @NotBlank(message = "user.validation.name.required")
        @Size(min = 2, max = 50, message = "user.validation.name.size")
        @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑ\\s]+$", message = "user.validation.name.format") // Permite acentos
        String name,
        
        @NotBlank(message = "user.validation.lastName.required")
        @Size(min = 2, max = 50, message = "user.validation.lastName.size")
        @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑ\\s]+$", message = "user.validation.lastName.format") // Permite acentos
        String lastName,
        
        @NotBlank(message = "user.validation.email.required")
        @Email(message = "user.validation.email.format")
        @Size(max = 100, message = "user.validation.email.size") // Consistente con entidad
        String email,
        
        // CORREGIDO: phoneNumber es OPCIONAL según la entidad
        @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "user.validation.phoneNumber.format") // Mismo patrón que entidad
        String phoneNumber, // Sin @NotBlank - es opcional
        
        @NotBlank(message = "user.validation.password.required")
        @Size(min = 8, max = 100, message = "user.validation.password.size")
        @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).*$", 
            message = "user.validation.password.format"
        )
        String password,


        @NotBlank(message = "user.validation.password.required")
        @Size(min = 8, max = 100, message = "user.validation.password.size")
        @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!]).*$", 
            message = "user.validation.password.format"
        )
        String confirmPassword,

        // CORREGIDO: dateOfBirth es OPCIONAL y sin @NotBlank (no aplica a LocalDate)
        @Past(message = "user.validation.dateOfBirth.past")
        LocalDate dateOfBirth, // Opcional, sin @NotBlank
        
        // ELIMINADO: role - se asigna automáticamente en el service
        // Los usuarios que se registran siempre son USER por defecto
        
        // OPCIONAL: Si quieres permitir términos y condiciones
        @AssertTrue(message = "user.validation.termsAccepted.required")
        Boolean termsAccepted
) {
    
    // Método de validación customizada si necesitas lógica adicional
    public boolean isValidForRegistration() {
        // Ejemplo: validar que sea mayor de 13 años si proporciona fecha
        if (dateOfBirth != null) {
            return java.time.Period.between(dateOfBirth, java.time.LocalDate.now()).getYears() >= 13;
        }
        return true;
    }
}