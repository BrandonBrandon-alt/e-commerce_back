package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "wishlist_items",
       uniqueConstraints = @UniqueConstraint(columnNames = {"wishlist_id", "product_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class WishlistItem {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con Wishlist (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wishlist_id", nullable = false)
    private Wishlist wishlist;
    
    // Relación con Product (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    // Precio cuando se agregó (para comparar cambios)
    @Column(name = "price_when_added", precision = 10, scale = 2)
    private BigDecimal priceWhenAdded;
    
    // Talla deseada (opcional)
    @Column(name = "desired_size", precision = 3, scale = 1)
    private BigDecimal desiredSize;
    
    // Notas personales sobre el producto
    @Column(name = "notes", length = 200)
    private String notes;
    
    // Prioridad del item
    @Enumerated(EnumType.STRING)
    @Column(name = "priority", nullable = false)
    private ItemPriority priority = ItemPriority.MEDIUM;
    
    // Notificaciones
    @Column(name = "notify_price_drop", nullable = false)
    private boolean notifyPriceDrop = false;
    
    @Column(name = "notify_back_in_stock", nullable = false)
    private boolean notifyBackInStock = false;
    
    // Fecha cuando se agregó
    @CreationTimestamp
    @Column(name = "added_at", updatable = false)
    private LocalDateTime addedAt;
    
    // Enum para prioridad
    public enum ItemPriority {
        LOW("Baja"),
        MEDIUM("Media"),
        HIGH("Alta"),
        URGENT("Urgente");
        
        private final String displayName;
        
        ItemPriority(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Verifica si el precio ha bajado desde que se agregó
     */
    public boolean hasPriceDropped() {
        if (priceWhenAdded == null || product == null || product.getPrice() == null) {
            return false;
        }
        return product.getPrice().compareTo(priceWhenAdded) < 0;
    }
    
    /**
     * Calcula el porcentaje de descuento si el precio bajó
     */
    public Double getPriceDropPercentage() {
        if (!hasPriceDropped()) return 0.0;
        
        BigDecimal difference = priceWhenAdded.subtract(product.getPrice());
        return (difference.doubleValue() / priceWhenAdded.doubleValue()) * 100;
    }
    
    /**
     * Obtiene la diferencia de precio
     */
    public BigDecimal getPriceDifference() {
        if (priceWhenAdded == null || product == null || product.getPrice() == null) {
            return BigDecimal.ZERO;
        }
        return product.getPrice().subtract(priceWhenAdded);
    }
    
    /**
     * Verifica si el producto está disponible en la talla deseada
     */
    public boolean isAvailableInDesiredSize() {
        if (desiredSize == null) {
            return product.hasStock();
        }
        return product.hasStockForSize(desiredSize);
    }
    
    /**
     * Obtiene la talla deseada formateada
     */
    public String getDesiredSizeFormatted() {
        if (desiredSize == null) return "Cualquiera";
        
        if (desiredSize.stripTrailingZeros().scale() <= 0) {
            return String.valueOf(desiredSize.intValue());
        }
        return desiredSize.toPlainString();
    }
    
    /**
     * Verifica si tiene notas
     */
    public boolean hasNotes() {
        return notes != null && !notes.trim().isEmpty();
    }
    
    /**
     * Verifica si el producto necesita notificación de stock
     */
    public boolean needsStockNotification() {
        return notifyBackInStock && !isAvailableInDesiredSize();
    }
    
    /**
     * Verifica si el producto necesita notificación de precio
     */
    public boolean needsPriceNotification() {
        return notifyPriceDrop && hasPriceDropped();
    }
}
