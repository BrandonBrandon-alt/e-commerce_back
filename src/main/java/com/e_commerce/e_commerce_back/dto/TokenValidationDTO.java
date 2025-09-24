package com.e_commerce.e_commerce_back.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO para respuesta de validación de token
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationDTO {
    
    @JsonProperty("valid")
    private boolean valid;
    
    @JsonProperty("username")
    private String username;
    
    @JsonProperty("expires_in")
    private Long expiresIn;
    
    @JsonProperty("timestamp")
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
    
    @JsonProperty("message")
    private String message;

    /**
     * Constructor para token válido
     */
    public static TokenValidationDTO valid(String username, Long expiresIn) {
        return TokenValidationDTO.builder()
                .valid(true)
                .username(username)
                .expiresIn(expiresIn)
                .message("Token válido")
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Constructor para token inválido
     */
    public static TokenValidationDTO invalid(String message) {
        return TokenValidationDTO.builder()
                .valid(false)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
