package com.e_commerce.e_commerce_back.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.e_commerce.e_commerce_back.entity.User;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfoDTO {
    
    private Long id;
    private String email;
    private String name;
    private String lastName;
    private String fullName;
    private String initials;
    
    // Enums convertidos a String para API limpia
    private String role;          // "USER", "ADMIN", "SELLER"
    private String status;        // "ACTIVE", "INACTIVE"
    
    private String phoneNumber;
    private Boolean emailVerified;
    private Boolean phoneVerified;
    private Integer age;
    
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateOfBirth;
    private Boolean isMinor;
    
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime lastLogin;
    private Boolean accountNonLocked;
    private Boolean credentialsNonExpired;
    private Boolean enabled;
    
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime createdAt;
    
    /**
     * @deprecated Este campo ya no se usa. Los intentos fallidos ahora se manejan en Redis.
     * Se mantiene por compatibilidad pero siempre retorna null.
     */
    @Deprecated
    private Integer failedLoginAttempts;
    
    /**
     * @deprecated Este campo ya no se usa. El bloqueo ahora se maneja en Redis.
     * Se mantiene por compatibilidad pero siempre retorna false.
     */
    @Deprecated
    private Boolean accountTemporarilyLocked;
    
    // Factory method principal - información completa
    public static UserInfoDTO fromUser(User user) {
        return UserInfoDTO.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .lastName(user.getLastName())
                .fullName(user.getFullName())
                .initials(user.getInitials())
                .role(user.getRole().name())                    // Enum → String
                .status(user.getStatus().name())                // Enum → String
                .phoneNumber(user.getPhoneNumber())
                .emailVerified(user.getEmailVerified())
                .phoneVerified(user.getPhoneVerified())
                .age(user.getAge())
                .dateOfBirth(user.getDateOfBirth())
                .isMinor(user.isMinor())
                .lastLogin(user.getLastLogin())
                .accountNonLocked(user.isAccountNonLocked())
                .credentialsNonExpired(user.isCredentialsNonExpired())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                // Campos deprecados - siempre null/false (datos ahora en Redis)
                .failedLoginAttempts(null)
                .accountTemporarilyLocked(false)
                .build();
    }
    
    // Factory method básico - información esencial
    public static UserInfoDTO fromUserBasic(User user) {
        return UserInfoDTO.builder()
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .lastName(user.getLastName())
                .fullName(user.getFullName())
                .initials(user.getInitials())
                .role(user.getRole().name())                    // Enum → String
                .status(user.getStatus().name())                // Enum → String
                .phoneNumber(user.getPhoneNumber())
                .emailVerified(user.getEmailVerified())
                .enabled(user.isEnabled())
                .createdAt(user.getCreatedAt())
                .build();
    }
    
    // Factory method público - sin información sensible
    public static UserInfoDTO fromUserPublic(User user) {
        return UserInfoDTO.builder()
                .id(user.getId())
                .name(user.getName())
                .lastName(user.getLastName())
                .fullName(user.getFullName())
                .initials(user.getInitials())
                .createdAt(user.getCreatedAt())
                .build();
    }
}