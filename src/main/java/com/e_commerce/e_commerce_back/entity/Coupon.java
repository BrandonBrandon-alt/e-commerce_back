package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Entidad que representa los cupones de descuento del sistema
 */
@Entity
@Table(name = "coupons", indexes = {
    @Index(name = "idx_coupon_code", columnList = "code", unique = true),
    @Index(name = "idx_coupon_user", columnList = "user_id"),
    @Index(name = "idx_coupon_status", columnList = "status"),
    @Index(name = "idx_coupon_type", columnList = "type"),
    @Index(name = "idx_coupon_valid_from", columnList = "valid_from"),
    @Index(name = "idx_coupon_valid_until", columnList = "valid_until"),
    @Index(name = "idx_coupon_created_at", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@ToString(exclude = {"user", "applicableProducts", "applicableCategories", "orders"})
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
public class Coupon extends BaseAuditableEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @NotBlank(message = "coupon.validation.code.required")
    @Size(min = 3, max = 50, message = "coupon.validation.code.size")
    @Pattern(regexp = "^[A-Z0-9_-]+$", message = "coupon.validation.code.format")
    @Column(name = "code", nullable = false, unique = true, length = 50)
    @EqualsAndHashCode.Include
    private String code;
    
    @NotBlank(message = "coupon.validation.name.required")
    @Size(max = 200, message = "coupon.validation.name.size")
    @Column(name = "name", nullable = false, length = 200)
    private String name;
    
    @Size(max = 1000, message = "coupon.validation.description.size")
    @Column(name = "description", length = 1000)
    private String description;
    
    @NotNull(message = "coupon.validation.type.required")
    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private CouponType type;
    
    @NotNull(message = "coupon.validation.discountValue.required")
    @DecimalMin(value = "0.01", message = "coupon.validation.discountValue.min")
    @Column(name = "discount_value", nullable = false, precision = 10, scale = 2)
    private BigDecimal discountValue;
    
    @DecimalMin(value = "0.00", message = "coupon.validation.minimumOrderAmount.min")
    @Column(name = "minimum_order_amount", precision = 10, scale = 2)
    private BigDecimal minimumOrderAmount;
    
    @DecimalMin(value = "0.00", message = "coupon.validation.maximumDiscountAmount.min")
    @Column(name = "maximum_discount_amount", precision = 10, scale = 2)
    private BigDecimal maximumDiscountAmount;
    
    @NotNull(message = "coupon.validation.validFrom.required")
    @Column(name = "valid_from", nullable = false)
    private LocalDateTime validFrom;
    
    @NotNull(message = "coupon.validation.validUntil.required")
    @Column(name = "valid_until", nullable = false)
    private LocalDateTime validUntil;
    
    @Min(value = 1, message = "coupon.validation.usageLimit.min")
    @Column(name = "usage_limit")
    private Integer usageLimit;
    
    @Min(value = 1, message = "coupon.validation.usageLimitPerUser.min")
    @Column(name = "usage_limit_per_user")
    private Integer usageLimitPerUser;
    
    @Column(name = "usage_count", nullable = false)
    @Builder.Default
    private Integer usageCount = 0;
    
    @NotNull(message = "coupon.validation.status.required")
    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private CouponStatus status = CouponStatus.ACTIVE;
    
    // Relación con usuario (para cupones personalizados)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;
    
    // Campos para segmentación y reglas
    @Column(name = "is_first_order_only", nullable = false)
    @Builder.Default
    private Boolean isFirstOrderOnly = false;
    
    @Column(name = "is_birthday_coupon", nullable = false)
    @Builder.Default
    private Boolean isBirthdayoupon = false;
    
    @Column(name = "is_referral_coupon", nullable = false)
    @Builder.Default
    private Boolean isReferralCoupon = false;
    
    @Column(name = "is_stackable", nullable = false)
    @Builder.Default
    private Boolean isStackable = false;
    
    @Column(name = "requires_membership", nullable = false)
    @Builder.Default
    private Boolean requiresMembership = false;
    
    @Column(name = "auto_apply", nullable = false)
    @Builder.Default
    private Boolean autoApply = false;
    
    // Campos para targeting geográfico
    @Column(name = "allowed_countries", length = 500)
    private String allowedCountries;
    
    @Column(name = "excluded_countries", length = 500)
    private String excludedCountries;
    
    // Campos para productos y categorías aplicables
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "coupon_products",
        joinColumns = @JoinColumn(name = "coupon_id"),
        inverseJoinColumns = @JoinColumn(name = "product_id")
    )
    @Builder.Default
    private List<Product> applicableProducts = Collections.emptyList();
    
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "coupon_categories",
        joinColumns = @JoinColumn(name = "coupon_id"),
        inverseJoinColumns = @JoinColumn(name = "category_id")
    )
    @Builder.Default
    private List<Category> applicableCategories = Collections.emptyList();
    
    // Relación con pedidos que usaron este cupón
    @OneToMany(mappedBy = "coupon", fetch = FetchType.LAZY)
    @Builder.Default
    private List<Order> orders = Collections.emptyList();
    
    // Campos para analytics y tracking
    @Column(name = "campaign_id", length = 100)
    private String campaignId;
    
    @Column(name = "source", length = 100)
    private String source;
    
    @Column(name = "medium", length = 100)
    private String medium;
    
    @Column(name = "tags", length = 500)
    private String tags;
    
    @Column(name = "created_by", length = 100)
    private String createdBy;
    
    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;
    
    // Enums
    public enum CouponType {
        PERCENTAGE("Porcentaje", "%"),
        FIXED_AMOUNT("Monto fijo", "$"),
        FREE_SHIPPING("Envío gratis", "🚚"),
        BUY_X_GET_Y("Compra X obtén Y", "🎁"),
        BUNDLE_DISCOUNT("Descuento por combo", "📦");
        
        private final String displayName;
        private final String symbol;
        
        CouponType(String displayName, String symbol) {
            this.displayName = displayName;
            this.symbol = symbol;
        }
        
        public String getDisplayName() { return displayName; }
        public String getSymbol() { return symbol; }
    }
    
    public enum CouponStatus {
        ACTIVE("Activo"),
        INACTIVE("Inactivo"),
        EXPIRED("Expirado"),
        EXHAUSTED("Agotado"),
        SUSPENDED("Suspendido"),
        DRAFT("Borrador");
        
        private final String displayName;
        
        CouponStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() { return displayName; }
    }
    
    // Métodos de negocio
    public boolean isValid() {
        return isActive() && !isExpired() && !isExhausted();
    }
    
    public boolean isActive() {
        return status == CouponStatus.ACTIVE;
    }
    
    public boolean isExpired() {
        LocalDateTime now = LocalDateTime.now();
        return now.isBefore(validFrom) || now.isAfter(validUntil);
    }
    
    public boolean isExhausted() {
        return usageLimit != null && usageCount >= usageLimit;
    }
    
    public boolean canBeUsedBy(User user) {
        if (!isValid()) return false;
        
        // Verificar si es cupón personal
        if (this.user != null && !this.user.equals(user)) {
            return false;
        }
        
        // Verificar límite por usuario
        if (usageLimitPerUser != null) {
            long userUsageCount = orders.stream()
                .filter(order -> order.getUser().equals(user))
                .count();
            if (userUsageCount >= usageLimitPerUser) {
                return false;
            }
        }
        
        // Verificar si es solo para primer pedido
        if (isFirstOrderOnly && user.getOrders() != null && !user.getOrders().isEmpty()) {
            return false;
        }
        
        return true;
    }
    
    public BigDecimal calculateDiscount(BigDecimal orderAmount) {
        if (!isValid() || orderAmount == null) {
            return BigDecimal.ZERO;
        }
        
        // Verificar monto mínimo
        if (minimumOrderAmount != null && orderAmount.compareTo(minimumOrderAmount) < 0) {
            return BigDecimal.ZERO;
        }
        
        BigDecimal discount = switch (type) {
            case PERCENTAGE -> orderAmount.multiply(discountValue).divide(BigDecimal.valueOf(100));
            case FIXED_AMOUNT -> discountValue;
            case FREE_SHIPPING -> BigDecimal.ZERO; // Se maneja en lógica de envío
            default -> BigDecimal.ZERO;
        };
        
        // Aplicar límite máximo de descuento
        if (maximumDiscountAmount != null && discount.compareTo(maximumDiscountAmount) > 0) {
            discount = maximumDiscountAmount;
        }
        
        // El descuento no puede ser mayor al monto del pedido
        if (discount.compareTo(orderAmount) > 0) {
            discount = orderAmount;
        }
        
        return discount;
    }
    
    public void incrementUsage() {
        this.usageCount = Objects.requireNonNullElse(this.usageCount, 0) + 1;
        this.lastUsedAt = LocalDateTime.now();
        
        // Marcar como agotado si alcanzó el límite
        if (usageLimit != null && usageCount >= usageLimit) {
            this.status = CouponStatus.EXHAUSTED;
        }
    }
    
    public void activate() {
        this.status = CouponStatus.ACTIVE;
    }
    
    public void deactivate() {
        this.status = CouponStatus.INACTIVE;
    }
    
    public void suspend() {
        this.status = CouponStatus.SUSPENDED;
    }
    
    public void expire() {
        this.status = CouponStatus.EXPIRED;
    }
    
    public String getFormattedDiscount() {
        return switch (type) {
            case PERCENTAGE -> discountValue + "%";
            case FIXED_AMOUNT -> "$" + discountValue;
            case FREE_SHIPPING -> "Envío gratis";
            default -> discountValue.toString();
        };
    }
    
    public String getUsageStatus() {
        if (usageLimit == null) {
            return "Uso ilimitado (" + usageCount + " usos)";
        }
        return usageCount + "/" + usageLimit + " usos";
    }
    
    public double getUsagePercentage() {
        if (usageLimit == null || usageLimit == 0) return 0.0;
        return (double) usageCount / usageLimit * 100;
    }
    
    public long getDaysUntilExpiry() {
        return java.time.temporal.ChronoUnit.DAYS.between(LocalDateTime.now(), validUntil);
    }
    
    public boolean isExpiringSoon() {
        return getDaysUntilExpiry() <= 7 && getDaysUntilExpiry() > 0;
    }
    
    public boolean isNewCoupon() {
        return getCreatedAt() != null && 
               getCreatedAt().isAfter(LocalDateTime.now().minusDays(7));
    }
    
    public boolean isPopular() {
        return usageCount != null && usageCount >= 100;
    }
    
    public String getStatusBadge() {
        return switch (status) {
            case ACTIVE -> "🟢 Activo";
            case INACTIVE -> "⚪ Inactivo";
            case EXPIRED -> "🔴 Expirado";
            case EXHAUSTED -> "🟠 Agotado";
            case SUSPENDED -> "🟡 Suspendido";
            case DRAFT -> "📝 Borrador";
        };
    }
    
    // JPA lifecycle methods
    @PrePersist
    protected void onCreate() {
        super.onCreate();
        if (status == null) {
            status = CouponStatus.ACTIVE;
        }
        if (usageCount == null) {
            usageCount = 0;
        }
        if (isFirstOrderOnly == null) {
            isFirstOrderOnly = false;
        }
        if (isBirthdayoupon == null) {
            isBirthdayoupon = false;
        }
        if (isReferralCoupon == null) {
            isReferralCoupon = false;
        }
        if (isStackable == null) {
            isStackable = false;
        }
        if (requiresMembership == null) {
            requiresMembership = false;
        }
        if (autoApply == null) {
            autoApply = false;
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        super.onUpdate();
        
        // Auto-expirar si pasó la fecha
        if (isExpired() && status == CouponStatus.ACTIVE) {
            this.status = CouponStatus.EXPIRED;
        }
    }

    
}