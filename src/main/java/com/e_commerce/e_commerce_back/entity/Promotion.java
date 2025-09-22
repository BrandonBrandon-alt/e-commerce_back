package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "promotions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Promotion {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Código del cupón/promoción
    @NotBlank(message = "El código es obligatorio")
    @Size(min = 3, max = 50, message = "El código debe tener entre 3 y 50 caracteres")
    @Column(name = "code", nullable = false, unique = true)
    private String code;
    
    // Nombre descriptivo
    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 100, message = "El nombre no puede exceder 100 caracteres")
    @Column(name = "name", nullable = false)
    private String name;
    
    // Descripción
    @Size(max = 500, message = "La descripción no puede exceder 500 caracteres")
    @Column(name = "description")
    private String description;
    
    // Tipo de descuento
    @Enumerated(EnumType.STRING)
    @Column(name = "discount_type", nullable = false)
    private DiscountType discountType;
    
    // Valor del descuento
    @NotNull(message = "El valor del descuento es obligatorio")
    @DecimalMin(value = "0.01", message = "El valor debe ser mayor a 0")
    @Column(name = "discount_value", nullable = false, precision = 10, scale = 2)
    private BigDecimal discountValue;
    
    // Descuento máximo (para porcentajes)
    @Column(name = "max_discount_amount", precision = 10, scale = 2)
    private BigDecimal maxDiscountAmount;
    
    // Monto mínimo de compra
    @Column(name = "minimum_purchase_amount", precision = 10, scale = 2)
    private BigDecimal minimumPurchaseAmount;
    
    // Fechas de validez
    @NotNull(message = "La fecha de inicio es obligatoria")
    @Column(name = "start_date", nullable = false)
    private LocalDateTime startDate;
    
    @NotNull(message = "La fecha de fin es obligatoria")
    @Column(name = "end_date", nullable = false)
    private LocalDateTime endDate;
    
    // Límites de uso
    @Column(name = "usage_limit")
    private Integer usageLimit; // null = ilimitado
    
    @Column(name = "usage_limit_per_user")
    private Integer usageLimitPerUser; // null = ilimitado
    
    @Column(name = "times_used", nullable = false)
    private Integer timesUsed = 0;
    
    // Aplicabilidad
    @Enumerated(EnumType.STRING)
    @Column(name = "applicable_to", nullable = false)
    private ApplicableTo applicableTo = ApplicableTo.ALL_PRODUCTS;
    
    // Productos específicos (si aplica)
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "promotion_products",
        joinColumns = @JoinColumn(name = "promotion_id"),
        inverseJoinColumns = @JoinColumn(name = "product_id")
    )
    private List<Product> applicableProducts = new ArrayList<>();
    
    // Categorías específicas (si aplica)
    @ElementCollection
    @Enumerated(EnumType.STRING)
    @CollectionTable(name = "promotion_categories", joinColumns = @JoinColumn(name = "promotion_id"))
    @Column(name = "category")
    private List<Product.ShoeCategory> applicableCategories = new ArrayList<>();
    
    // Usuarios específicos (si aplica)
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "promotion_users",
        joinColumns = @JoinColumn(name = "promotion_id"),
        inverseJoinColumns = @JoinColumn(name = "user_id")
    )
    private List<User> applicableUsers = new ArrayList<>();
    
    // Estado de la promoción
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
    
    @Column(name = "is_public", nullable = false)
    private boolean isPublic = true; // Si es false, solo usuarios específicos pueden usarla
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Enums
    public enum DiscountType {
        PERCENTAGE("Porcentaje"),
        FIXED_AMOUNT("Monto Fijo"),
        FREE_SHIPPING("Envío Gratis"),
        BUY_X_GET_Y("Compra X Lleva Y");
        
        private final String displayName;
        
        DiscountType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum ApplicableTo {
        ALL_PRODUCTS("Todos los Productos"),
        SPECIFIC_PRODUCTS("Productos Específicos"),
        SPECIFIC_CATEGORIES("Categorías Específicas"),
        SPECIFIC_USERS("Usuarios Específicos");
        
        private final String displayName;
        
        ApplicableTo(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Verifica si la promoción está vigente
     */
    public boolean isValid() {
        LocalDateTime now = LocalDateTime.now();
        return isActive && 
               now.isAfter(startDate) && 
               now.isBefore(endDate) &&
               !isUsageLimitReached();
    }
    
    /**
     * Verifica si se alcanzó el límite de uso
     */
    public boolean isUsageLimitReached() {
        return usageLimit != null && timesUsed >= usageLimit;
    }
    
    /**
     * Verifica si un usuario puede usar la promoción
     */
    public boolean canUserUse(User user, Integer userUsageCount) {
        if (!isValid()) return false;
        
        // Verificar límite por usuario
        if (usageLimitPerUser != null && userUsageCount >= usageLimitPerUser) {
            return false;
        }
        
        // Si es para usuarios específicos, verificar que esté en la lista
        if (applicableTo == ApplicableTo.SPECIFIC_USERS) {
            return applicableUsers.contains(user);
        }
        
        return isPublic;
    }
    
    /**
     * Verifica si la promoción aplica a un producto
     */
    public boolean appliesTo(Product product) {
        switch (applicableTo) {
            case ALL_PRODUCTS:
                return true;
            case SPECIFIC_PRODUCTS:
                return applicableProducts.contains(product);
            case SPECIFIC_CATEGORIES:
                return applicableCategories.contains(product.getCategory());
            default:
                return false;
        }
    }
    
    /**
     * Calcula el descuento para un monto dado
     */
    public BigDecimal calculateDiscount(BigDecimal amount) {
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            return BigDecimal.ZERO;
        }
        
        // Verificar monto mínimo
        if (minimumPurchaseAmount != null && amount.compareTo(minimumPurchaseAmount) < 0) {
            return BigDecimal.ZERO;
        }
        
        BigDecimal discount = BigDecimal.ZERO;
        
        switch (discountType) {
            case PERCENTAGE:
                discount = amount.multiply(discountValue).divide(BigDecimal.valueOf(100));
                // Aplicar descuento máximo si está definido
                if (maxDiscountAmount != null && discount.compareTo(maxDiscountAmount) > 0) {
                    discount = maxDiscountAmount;
                }
                break;
            case FIXED_AMOUNT:
                discount = discountValue;
                // El descuento no puede ser mayor al monto
                if (discount.compareTo(amount) > 0) {
                    discount = amount;
                }
                break;
            case FREE_SHIPPING:
                // Este tipo se maneja en la lógica de envío
                discount = BigDecimal.ZERO;
                break;
            case BUY_X_GET_Y:
                // Este tipo requiere lógica especial en el carrito/orden
                discount = BigDecimal.ZERO;
                break;
        }
        
        return discount;
    }
    
    /**
     * Incrementa el contador de uso
     */
    public void incrementUsage() {
        this.timesUsed++;
    }
    
    /**
     * Obtiene los usos restantes
     */
    public Integer getRemainingUses() {
        if (usageLimit == null) return null; // Ilimitado
        return Math.max(0, usageLimit - timesUsed);
    }
    
    /**
     * Verifica si es un descuento de envío gratis
     */
    public boolean isFreeShipping() {
        return discountType == DiscountType.FREE_SHIPPING;
    }
    
    /**
     * Obtiene el porcentaje de uso
     */
    public Double getUsagePercentage() {
        if (usageLimit == null) return 0.0;
        return (timesUsed.doubleValue() / usageLimit.doubleValue()) * 100;
    }
}
