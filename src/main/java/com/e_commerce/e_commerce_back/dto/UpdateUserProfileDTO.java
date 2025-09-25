package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UpdateUserProfileDTO(
     @Size(min = 2, max = 50, message = "user.validation.name.size")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑ\\s]*$", message = "user.validation.name.format")
    String name,
    
    @Size(min = 2, max = 50, message = "user.validation.lastName.size")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑ\\s]*$", message = "user.validation.lastName.format")
    String lastName,
    
    @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "user.validation.phoneNumber.format")
    String phoneNumber
) {
}