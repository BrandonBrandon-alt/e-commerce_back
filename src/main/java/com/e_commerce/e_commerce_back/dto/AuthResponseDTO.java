package com.e_commerce.e_commerce_back.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO de respuesta para operaciones de autenticación
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {
    
    @JsonProperty("access_token")
    private String accessToken;
    
    @JsonProperty("refresh_token")
    private String refreshToken;
    
    @JsonProperty("token_type")
    @Builder.Default
    private String tokenType = "Bearer";
    
    @JsonProperty("expires_in")
    private Long expiresIn;
    
    @JsonProperty("user_info")
    private UserInfoDTO userInfo;
    
    @JsonProperty("timestamp")
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
    
    @JsonProperty("message")
    private String message;

    /**
     * Constructor para respuesta exitosa de login con tokens
     */
    public static AuthResponseDTO success(String accessToken, String refreshToken, Long expiresIn, UserInfoDTO userInfo) {
        return AuthResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .userInfo(userInfo)
                .message("Autenticación exitosa")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Constructor para respuesta exitosa de login (sin refresh token - legacy)
     */
    public static AuthResponseDTO success(String accessToken, Long expiresIn, UserInfoDTO userInfo) {
        return AuthResponseDTO.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .userInfo(userInfo)
                .message("Autenticación exitosa")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Constructor para respuesta exitosa de refresh token
     */
    public static AuthResponseDTO refreshSuccess(String accessToken, String refreshToken, Long expiresIn) {
        return AuthResponseDTO.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(expiresIn)
                .message("Tokens renovados exitosamente")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Constructor para respuesta exitosa de registro
     */
    public static AuthResponseDTO registered(String message) {
        return AuthResponseDTO.builder()
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Constructor para respuesta exitosa simple
     */
    public static AuthResponseDTO success(String message) {
        return AuthResponseDTO.builder()
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Constructor para respuesta de error
     */
    public static AuthResponseDTO error(String message) {
        return AuthResponseDTO.builder()
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }


    /**
 * Constructor para respuesta exitosa con información de usuario
 */
public static AuthResponseDTO successWithUserInfo(String message, UserInfoDTO userInfo) {
    return AuthResponseDTO.builder()
            .message(message)
            .userInfo(userInfo)
            .timestamp(LocalDateTime.now())
            .build();
}
}