package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * DTO para login con Google OAuth2
 * Recibe el token de ID de Google desde el frontend
 */
public record GoogleOAuthLoginDTO(
        @NotBlank(message = "Google ID token is required")
        String idToken
) {
}
