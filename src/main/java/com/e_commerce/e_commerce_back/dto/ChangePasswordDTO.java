package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordDTO(
     @NotBlank(message = "user.validation.currentPassword.required")
    String currentPassword,
    
    @NotBlank(message = "user.validation.password.required")
    @Size(min = 8, max = 100, message = "user.validation.password.size")
    String newPassword,
    
    @NotBlank(message = "user.validation.confirmPassword.required")
    String confirmPassword
)
{
    public boolean isPasswordConfirmationValid() {
        return newPassword != null && newPassword.equals(confirmPassword);
    }

}