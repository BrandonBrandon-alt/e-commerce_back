package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.e_commerce.enums.EnumStatus;
import com.e_commerce.enums.EnumRole;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.Period;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_id_number", columnList = "id_number"),
        @Index(name = "idx_user_status_role", columnList = "status, role"),
        @Index(name = "idx_user_created_at", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@ToString(exclude = { "password", "orders",
        "addresses", "cart" })
public class User extends BaseAuditableEntity implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotBlank(message = "user.validation.idNumber.required")
    @Size(min = 2, max = 15, message = "user.validation.idNumber.size")
    @Pattern(regexp = "^[0-9A-Za-z-]+$", message = "user.validation.idNumber.format")
    @Column(name = "id_number", nullable = false, length = 15, unique = true)
    private String idNumber;

    @NotBlank(message = "user.validation.name.required")
    @Size(min = 2, max = 50, message = "user.validation.name.size")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑ\\s]+$", message = "user.validation.name.format")
    @Column(name = "name", nullable = false, length = 50)
    private String name;

    @NotBlank(message = "user.validation.lastName.required")
    @Size(min = 2, max = 50, message = "user.validation.lastName.size")
    @Pattern(regexp = "^[a-zA-ZáéíóúÁÉÍÓÚñÑ\\s]+$", message = "user.validation.lastName.format")
    @Column(name = "last_name", nullable = false, length = 50)
    private String lastName;

    @Past(message = "user.validation.dateOfBirth.past")
    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @NotBlank(message = "user.validation.email.required")
    @Email(message = "user.validation.email.format")
    @Size(max = 100, message = "user.validation.email.size")
    @Column(name = "email", nullable = false, unique = true, length = 100)
    @EqualsAndHashCode.Include
    private String email;

    @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "user.validation.phoneNumber.format")
    @Column(name = "phone_number", length = 20)
    private String phoneNumber;

    @NotBlank(message = "user.validation.password.required")
    @Size(min = 8, max = 100, message = "user.validation.password.size")
    @Column(name = "password", nullable = false, length = 255)
    private String password;

    @NotNull(message = "user.validation.role.required")
    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private EnumRole role = EnumRole.USER;

    @NotNull(message = "user.validation.status.required")
    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private EnumStatus status = EnumStatus.INACTIVE;

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    /**
     * @deprecated Este campo ya no se usa. El bloqueo de cuentas ahora se maneja en
     *             Redis.
     *             Mantenido temporalmente para compatibilidad con datos existentes.
     *             Será eliminado en una versión futura.
     */
    @Deprecated
    @Column(name = "account_locked_until")
    private LocalDateTime accountLockedUntil;

    @Column(name = "password_changed_at")
    private LocalDateTime passwordChangedAt;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private Boolean emailVerified = false;

    @Column(name = "phone_verified", nullable = false)
    @Builder.Default
    private Boolean phoneVerified = false;

    @Column(name = "last_ip_address", length = 45)
    private String lastIpAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Order> orders = Collections.emptyList();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Address> addresses = Collections.emptyList();

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private Cart cart;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private Wishlist wishlist;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Review> reviews = Collections.emptyList();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Rating> ratings = Collections.emptyList();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Favorite> favorites = Collections.emptyList();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Notification> notifications = Collections.emptyList();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    @Builder.Default
    private List<Coupon> personalCoupons = Collections.emptyList();

    // Spring Security UserDetails implementation
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountLockedUntil == null || accountLockedUntil.isBefore(LocalDateTime.now());
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return passwordChangedAt == null ||
                passwordChangedAt.isAfter(LocalDateTime.now().minusMonths(6));
    }

    @Override
    public boolean isEnabled() {
        return status == EnumStatus.ACTIVE && Boolean.TRUE.equals(emailVerified);
    }

    // Business methods
    public String getFullName() {
        return String.format("%s %s",
                Objects.requireNonNullElse(name, ""),
                Objects.requireNonNullElse(lastName, "")).trim();
    }

    public String getInitials() {
        String firstInitial = name != null && !name.isEmpty() ? String.valueOf(name.charAt(0)).toUpperCase() : "";
        String lastInitial = lastName != null && !lastName.isEmpty() ? String.valueOf(lastName.charAt(0)).toUpperCase()
                : "";
        return firstInitial + lastInitial;
    }

    public Integer getAge() {
        return dateOfBirth != null ? Period.between(dateOfBirth, LocalDate.now()).getYears() : null;
    }

    public boolean isMinor() {
        Integer age = getAge();
        return age != null && age < 18;
    }

    // Role checking methods
    public boolean isAdmin() {
        return role == EnumRole.ADMIN;
    }

    public boolean isUser() {
        return role == EnumRole.USER;
    }

    public boolean isSeller() {
        return role == EnumRole.SELLER;
    }

    // Status checking methods
    public boolean isActive() {
        return status == EnumStatus.ACTIVE;
    }

    public boolean isInactive() {
        return status == EnumStatus.INACTIVE;
    }

    /**
     * @deprecated El bloqueo de cuentas ahora se maneja en Redis mediante
     *             AccountLockoutRedisService.
     *             Este método se mantiene solo para compatibilidad con código
     *             legacy.
     */
    @Deprecated
    public boolean isAccountTemporarilyLocked() {
        return accountLockedUntil != null &&
                accountLockedUntil.isAfter(LocalDateTime.now());
    }

    // Security methods

    /**
     * @deprecated El bloqueo de cuentas ahora se maneja en Redis mediante
     *             AccountLockoutRedisService.
     *             Este método se mantiene solo para compatibilidad con código
     *             legacy.
     */
    @Deprecated
    public void lockAccount(int minutesToLock) {
        this.accountLockedUntil = LocalDateTime.now().plusMinutes(minutesToLock);
    }

    /**
     * Resetea el bloqueo de cuenta (solo limpia datos legacy de BD).
     * El bloqueo real ahora se maneja en Redis.
     */
    public void resetAccountLock() {
        this.accountLockedUntil = null;
    }

    public void markPhoneAsVerified() {
        this.phoneVerified = true;
    }

    // Cleanup methods
    public void updateLastLogin(String ipAddress, String userAgent) {
        this.lastLogin = LocalDateTime.now();
        this.lastIpAddress = ipAddress;
        this.userAgent = userAgent;
    }

    // JPA lifecycle methods
    @PrePersist
    protected void onCreate() {
        super.onCreate();
        if (status == null) {
            status = EnumStatus.INACTIVE;
        }
        if (role == null) {
            role = EnumRole.USER;
        }
        if (emailVerified == null) {
            emailVerified = false;
        }
        if (phoneVerified == null) {
            phoneVerified = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        super.onUpdate();
    }
}