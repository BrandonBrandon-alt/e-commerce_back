package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
/**
 * DTO para reset de contraseña con validaciones
 */
public record ResetPasswordDTO(
    
     @NotBlank(message = "El código de reset es requerido")
     @Pattern(regexp = "^[0-9]{6}$", message = "El código de reset debe ser de 6 dígitos")
     String resetCode,
        
    @NotBlank(message = "La contraseña es obligatoria") @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres") @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", message = "La contraseña debe contener al menos: 1 número, 1 minúscula, 1 mayúscula y 1 carácter especial") String password,
    
    @NotBlank(message = "La confirmación de contraseña es obligatoria") @Size(min = 8, max = 100, message = "La contraseña debe tener entre 8 y 100 caracteres") @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", message = "La contraseña debe contener al menos: 1 número, 1 minúscula, 1 mayúscula y 1 carácter especial") String confirmPassword
    
) {
    
    /**
     * Valida que las contraseñas coincidan
     */
    public boolean passwordsMatch() {
        return password != null && password.equals(confirmPassword);
    }
    
}