package com.e_commerce.e_commerce_back.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenDTO(
        @NotBlank(message = "El token de refresco no puede estar vacío") String refreshToken) {
}