package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "addresses")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Address {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con User (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    // Tipo de dirección
    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false)
    private AddressType type;
    
    // Información del destinatario
    @NotBlank(message = "El nombre del destinatario es obligatorio")
    @Size(min = 2, max = 100, message = "El nombre debe tener entre 2 y 100 caracteres")
    @Column(name = "recipient_name", nullable = false)
    private String recipientName;
    
    @Pattern(regexp = "^[+]?[0-9]{10,15}$", message = "Formato de teléfono inválido")
    @Column(name = "phone_number")
    private String phoneNumber;
    
    // Dirección
    @NotBlank(message = "La calle es obligatoria")
    @Size(max = 200, message = "La calle no puede exceder 200 caracteres")
    @Column(name = "street", nullable = false)
    private String street;
    
    @Size(max = 10, message = "El número exterior no puede exceder 10 caracteres")
    @Column(name = "exterior_number")
    private String exteriorNumber;
    
    @Size(max = 10, message = "El número interior no puede exceder 10 caracteres")
    @Column(name = "interior_number")
    private String interiorNumber;
    
    @Size(max = 100, message = "La colonia no puede exceder 100 caracteres")
    @Column(name = "neighborhood")
    private String neighborhood;
    
    @NotBlank(message = "La ciudad es obligatoria")
    @Size(max = 100, message = "La ciudad no puede exceder 100 caracteres")
    @Column(name = "city", nullable = false)
    private String city;
    
    @NotBlank(message = "El estado es obligatorio")
    @Size(max = 100, message = "El estado no puede exceder 100 caracteres")
    @Column(name = "state", nullable = false)
    private String state;
    
    @NotBlank(message = "El código postal es obligatorio")
    @Pattern(regexp = "^[0-9]{5}$", message = "El código postal debe tener 5 dígitos")
    @Column(name = "postal_code", nullable = false)
    private String postalCode;
    
    @NotBlank(message = "El país es obligatorio")
    @Size(max = 100, message = "El país no puede exceder 100 caracteres")
    @Column(name = "country", nullable = false)
    private String country = "México";
    
    // Referencias adicionales
    @Size(max = 200, message = "Las referencias no pueden exceder 200 caracteres")
    @Column(name = "references")
    private String references;
    
    // Configuraciones
    @Column(name = "is_default", nullable = false)
    private boolean isDefault = false;
    
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Enum para tipo de dirección
    public enum AddressType {
        HOME("Casa"),
        WORK("Trabajo"),
        OTHER("Otro");
        
        private final String displayName;
        
        AddressType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Obtiene la dirección completa formateada
     */
    public String getFullAddress() {
        StringBuilder address = new StringBuilder();
        
        address.append(street);
        
        if (exteriorNumber != null && !exteriorNumber.trim().isEmpty()) {
            address.append(" ").append(exteriorNumber);
        }
        
        if (interiorNumber != null && !interiorNumber.trim().isEmpty()) {
            address.append(" Int. ").append(interiorNumber);
        }
        
        if (neighborhood != null && !neighborhood.trim().isEmpty()) {
            address.append(", ").append(neighborhood);
        }
        
        address.append(", ").append(city);
        address.append(", ").append(state);
        address.append(" ").append(postalCode);
        address.append(", ").append(country);
        
        return address.toString();
    }
    
    /**
     * Obtiene la dirección resumida (calle, ciudad, estado)
     */
    public String getShortAddress() {
        StringBuilder address = new StringBuilder();
        
        address.append(street);
        if (exteriorNumber != null && !exteriorNumber.trim().isEmpty()) {
            address.append(" ").append(exteriorNumber);
        }
        address.append(", ").append(city);
        address.append(", ").append(state);
        
        return address.toString();
    }
    
    /**
     * Verifica si la dirección está completa
     */
    public boolean isComplete() {
        return recipientName != null && !recipientName.trim().isEmpty() &&
               street != null && !street.trim().isEmpty() &&
               city != null && !city.trim().isEmpty() &&
               state != null && !state.trim().isEmpty() &&
               postalCode != null && !postalCode.trim().isEmpty() &&
               country != null && !country.trim().isEmpty();
    }
    
    /**
     * Marca esta dirección como predeterminada
     */
    public void setAsDefault() {
        this.isDefault = true;
    }
    
    /**
     * Remueve el estado de dirección predeterminada
     */
    public void removeDefault() {
        this.isDefault = false;
    }
}
