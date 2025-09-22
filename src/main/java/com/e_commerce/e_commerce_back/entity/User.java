package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import com.e_commerce.e_commerce_back.entity.Role;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 2, max = 50, message = "El nombre debe tener entre 2 y 50 caracteres")
    @Column(name = "name", nullable = false, length = 50)
    private String name;
    
    @NotBlank(message = "El apellido es obligatorio")
    @Size(min = 2, max = 50, message = "El apellido debe tener entre 2 y 50 caracteres")
    @Column(name = "last_name", nullable = false, length = 50)
    private String lastName;
    
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe tener un formato válido")
    @Column(name = "email", nullable = false, unique = true, length = 100)
    private String email;
    
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 8, message = "La contraseña debe tener al menos 8 caracteres")
    @Column(name = "password", nullable = false)
    private String password;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role = Role.BUYER;
    
    @Column(name = "enabled", nullable = false)
    private boolean enabled = false;
    
    @Column(name = "token", length = 500)
    private String token;
    
    // Campos adicionales importantes
    @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "Formato de teléfono inválido")
    @Column(name = "phone_number", length = 20)
    private String phoneNumber;
    
    @Column(name = "date_of_birth")
    private LocalDateTime dateOfBirth;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "gender")
    private Gender gender;
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "last_login")
    private LocalDateTime lastLogin;
    
    // Campos de verificación
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;
    
    @Column(name = "verification_token", length = 500)
    private String verificationToken;
    
    @Column(name = "verification_token_expiry")
    private LocalDateTime verificationTokenExpiry;
    
    // Campos de recuperación de contraseña
    @Column(name = "reset_password_token", length = 500)
    private String resetPasswordToken;
    
    @Column(name = "reset_password_expiry")
    private LocalDateTime resetPasswordExpiry;
    
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Order> orders;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Address> addresses;
    
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private Cart cart;
    
    
    // Métodos útiles
    public String getFullName() {
        return name + " " + lastName;
    }
    
    public boolean isAdmin() {
        return role == Role.ADMIN;
    }
    
    public boolean isBuyer() {
        return role == Role.BUYER;
    }
    
    public boolean isTokenExpired() {
        return verificationTokenExpiry != null && 
               verificationTokenExpiry.isBefore(LocalDateTime.now());
    }
    
    public boolean isResetTokenExpired() {
        return resetPasswordExpiry != null && 
               resetPasswordExpiry.isBefore(LocalDateTime.now());
    }
}