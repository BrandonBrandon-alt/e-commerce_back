package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "wishlists")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Wishlist {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con User (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    // Nombre de la lista
    @NotBlank(message = "El nombre de la lista es obligatorio")
    @Size(min = 2, max = 100, message = "El nombre debe tener entre 2 y 100 caracteres")
    @Column(name = "name", nullable = false)
    private String name;
    
    // Descripción opcional
    @Size(max = 500, message = "La descripción no puede exceder 500 caracteres")
    @Column(name = "description")
    private String description;
    
    // Tipo de lista
    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false)
    private WishlistType type = WishlistType.PERSONAL;
    
    // Visibilidad
    @Enumerated(EnumType.STRING)
    @Column(name = "visibility", nullable = false)
    private WishlistVisibility visibility = WishlistVisibility.PRIVATE;
    
    // Items de la lista
    @OneToMany(mappedBy = "wishlist", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<WishlistItem> items = new ArrayList<>();
    
    // Lista predeterminada del usuario
    @Column(name = "is_default", nullable = false)
    private boolean isDefault = false;
    
    // Estado activo
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Enums
    public enum WishlistType {
        PERSONAL("Personal"),
        GIFT_REGISTRY("Lista de Regalos"),
        WEDDING("Boda"),
        BIRTHDAY("Cumpleaños"),
        BABY_SHOWER("Baby Shower"),
        CHRISTMAS("Navidad"),
        OTHER("Otro");
        
        private final String displayName;
        
        WishlistType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum WishlistVisibility {
        PRIVATE("Privada"),
        PUBLIC("Pública"),
        SHARED("Compartida");
        
        private final String displayName;
        
        WishlistVisibility(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Agrega un producto a la lista
     */
    public void addProduct(Product product) {
        if (!containsProduct(product)) {
            WishlistItem item = new WishlistItem();
            item.setWishlist(this);
            item.setProduct(product);
            item.setPriceWhenAdded(product.getPrice());
            items.add(item);
        }
    }
    
    /**
     * Remueve un producto de la lista
     */
    public void removeProduct(Product product) {
        items.removeIf(item -> item.getProduct().getId().equals(product.getId()));
    }
    
    /**
     * Verifica si un producto está en la lista
     */
    public boolean containsProduct(Product product) {
        return items.stream()
                   .anyMatch(item -> item.getProduct().getId().equals(product.getId()));
    }
    
    /**
     * Obtiene el número total de items
     */
    public Integer getTotalItems() {
        return items.size();
    }
    
    /**
     * Verifica si la lista está vacía
     */
    public boolean isEmpty() {
        return items == null || items.isEmpty();
    }
    
    /**
     * Limpia toda la lista
     */
    public void clearList() {
        items.clear();
    }
    
    /**
     * Verifica si la lista es pública
     */
    public boolean isPublic() {
        return visibility == WishlistVisibility.PUBLIC;
    }
    
    /**
     * Verifica si la lista es privada
     */
    public boolean isPrivate() {
        return visibility == WishlistVisibility.PRIVATE;
    }
    
    /**
     * Verifica si la lista es compartida
     */
    public boolean isShared() {
        return visibility == WishlistVisibility.SHARED;
    }
    
    /**
     * Marca como lista predeterminada
     */
    public void setAsDefault() {
        this.isDefault = true;
    }
    
    /**
     * Remueve el estado de lista predeterminada
     */
    public void removeDefault() {
        this.isDefault = false;
    }
    
    /**
     * Obtiene los productos disponibles (con stock)
     */
    public List<Product> getAvailableProducts() {
        return items.stream()
                   .map(WishlistItem::getProduct)
                   .filter(Product::isAvailable)
                   .toList();
    }
    
    /**
     * Obtiene los productos sin stock
     */
    public List<Product> getOutOfStockProducts() {
        return items.stream()
                   .map(WishlistItem::getProduct)
                   .filter(product -> !product.hasStock())
                   .toList();
    }
}
