package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangeEmailDTO(
        @NotBlank(message = "user.validation.email.required") @Email(message = "user.validation.email.format") @Size(max = 100, message = "user.validation.email.size") String newEmail,

        @NotBlank(message = "user.validation.currentPassword.required") String currentPassword) {
}