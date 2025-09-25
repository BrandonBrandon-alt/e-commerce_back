package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Entidad que representa los productos favoritos de los usuarios
 */
@Entity
@Table(name = "favorites", indexes = {
    @Index(name = "idx_favorite_user_product", columnList = "user_id, product_id", unique = true),
    @Index(name = "idx_favorite_user", columnList = "user_id"),
    @Index(name = "idx_favorite_product", columnList = "product_id"),
    @Index(name = "idx_favorite_created_at", columnList = "created_at"),
    @Index(name = "idx_favorite_priority", columnList = "priority")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@ToString(exclude = {"user", "product"})
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
public class Favorite extends BaseAuditableEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @NotNull(message = "favorite.validation.user.required")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @NotNull(message = "favorite.validation.product.required")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    @Min(value = 1, message = "favorite.validation.priority.min")
    @Max(value = 10, message = "favorite.validation.priority.max")
    @Column(name = "priority")
    private Integer priority;
    
    @Size(max = 500, message = "favorite.validation.notes.size")
    @Column(name = "notes", length = 500)
    private String notes;
    
    @Column(name = "notify_price_drop", nullable = false)
    @Builder.Default
    private Boolean notifyPriceDrop = true;
    
    @Column(name = "notify_back_in_stock", nullable = false)
    @Builder.Default
    private Boolean notifyBackInStock = true;
    
    @Column(name = "notify_promotion", nullable = false)
    @Builder.Default
    private Boolean notifyPromotion = true;
    
    @Column(name = "target_price")
    private Double targetPrice;
    
    @Column(name = "last_price_check")
    private Double lastPriceCheck;
    
    @Column(name = "last_price_check_date")
    private LocalDateTime lastPriceCheckDate;
    
    @Column(name = "times_viewed", nullable = false)
    @Builder.Default
    private Integer timesViewed = 0;
    
    @Column(name = "last_viewed_at")
    private LocalDateTime lastViewedAt;
    
    @Column(name = "category", length = 50)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private FavoriteCategory category = FavoriteCategory.GENERAL;
    
    @Column(name = "is_public", nullable = false)
    @Builder.Default
    private Boolean isPublic = false;
    
    @Column(name = "shared_count", nullable = false)
    @Builder.Default
    private Integer sharedCount = 0;
    
    // Enum para categorías de favoritos
    public enum FavoriteCategory {
        GENERAL("General"),
        WISHLIST("Lista de deseos"),
        GIFT_IDEAS("Ideas de regalo"),
        PRICE_WATCH("Seguimiento de precio"),
        SEASONAL("Temporada"),
        COLLECTION("Colección"),
        COMPARISON("Comparación");
        
        private final String displayName;
        
        FavoriteCategory(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos de negocio
    public boolean hasTargetPrice() {
        return targetPrice != null && targetPrice > 0;
    }
    
    public boolean isPriceDropAlert() {
        return hasTargetPrice() && lastPriceCheck != null && 
               lastPriceCheck <= targetPrice;
    }
    
    public Double getPriceDropPercentage() {
        if (lastPriceCheck == null || targetPrice == null || targetPrice == 0) {
            return 0.0;
        }
        return ((targetPrice - lastPriceCheck) / targetPrice) * 100;
    }
    
    public boolean isHighPriority() {
        return priority != null && priority >= 8;
    }
    
    public boolean isMediumPriority() {
        return priority != null && priority >= 5 && priority < 8;
    }
    
    public boolean isLowPriority() {
        return priority != null && priority < 5;
    }
    
    public boolean isRecentlyViewed() {
        return lastViewedAt != null && 
               lastViewedAt.isAfter(LocalDateTime.now().minusDays(7));
    }
    
    public boolean isFrequentlyViewed() {
        return timesViewed != null && timesViewed >= 10;
    }
    
    public void incrementView() {
        this.timesViewed = Objects.requireNonNullElse(this.timesViewed, 0) + 1;
        this.lastViewedAt = LocalDateTime.now();
    }
    
    public void updatePriceCheck(Double currentPrice) {
        this.lastPriceCheck = currentPrice;
        this.lastPriceCheckDate = LocalDateTime.now();
    }
    
    public void incrementSharedCount() {
        this.sharedCount = Objects.requireNonNullElse(this.sharedCount, 0) + 1;
    }
    
    public String getPriorityDescription() {
        if (priority == null) return "Sin prioridad";
        
        if (priority >= 9) return "🔥 Muy alta";
        if (priority >= 7) return "⭐ Alta";
        if (priority >= 5) return "📌 Media";
        if (priority >= 3) return "📋 Baja";
        return "📝 Muy baja";
    }
    
    public boolean shouldNotifyPriceDrop(Double currentPrice) {
        return notifyPriceDrop && hasTargetPrice() && 
               currentPrice != null && currentPrice <= targetPrice;
    }
    
    public boolean shouldNotifyBackInStock(boolean isInStock) {
        return notifyBackInStock && isInStock;
    }
    
    public boolean shouldNotifyPromotion() {
        return notifyPromotion;
    }
    
    public long getDaysSinceFavorited() {
        if (getCreatedAt() == null) return 0;
        return java.time.temporal.ChronoUnit.DAYS.between(
            getCreatedAt().toLocalDate(), 
            LocalDateTime.now().toLocalDate()
        );
    }
    
    // JPA lifecycle methods
    @PrePersist
    protected void onCreate() {
        super.onCreate();
        if (category == null) {
            category = FavoriteCategory.GENERAL;
        }
        if (notifyPriceDrop == null) {
            notifyPriceDrop = true;
        }
        if (notifyBackInStock == null) {
            notifyBackInStock = true;
        }
        if (notifyPromotion == null) {
            notifyPromotion = true;
        }
        if (timesViewed == null) {
            timesViewed = 0;
        }
        if (isPublic == null) {
            isPublic = false;
        }
        if (sharedCount == null) {
            sharedCount = 0;
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        super.onUpdate();
    }
}
