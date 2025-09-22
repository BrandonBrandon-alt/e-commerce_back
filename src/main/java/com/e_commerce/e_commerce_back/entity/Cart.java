package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
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
@Table(name = "carts")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Cart {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con User (uno a uno)
    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;
    
    // Relación con CartItems (uno a muchos)
    @OneToMany(mappedBy = "cart", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<CartItem> items = new ArrayList<>();
    
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    
    // Métodos útiles para el carrito
    
    /**
     * Agrega un producto al carrito
     * Si ya existe, aumenta la cantidad
     */
    public void addItem(Product product, Integer quantity) {
        CartItem existingItem = findItemByProduct(product);
        
        if (existingItem != null) {
            existingItem.setQuantity(existingItem.getQuantity() + quantity);
        } else {
            CartItem newItem = new CartItem();
            newItem.setCart(this);
            newItem.setProduct(product);
            newItem.setQuantity(quantity);
            newItem.setPrice(product.getPrice());
            items.add(newItem);
        }
    }
    
    /**
     * Remueve un producto del carrito
     */
    public void removeItem(Product product) {
        items.removeIf(item -> item.getProduct().getId().equals(product.getId()));
    }
    
    /**
     * Actualiza la cantidad de un producto
     */
    public void updateItemQuantity(Product product, Integer newQuantity) {
        if (newQuantity <= 0) {
            removeItem(product);
            return;
        }
        
        CartItem item = findItemByProduct(product);
        if (item != null) {
            item.setQuantity(newQuantity);
        }
    }
    
    /**
     * Calcula el total del carrito
     */
    public BigDecimal getTotalAmount() {
        return items.stream()
                   .map(CartItem::getSubtotal)
                   .reduce(BigDecimal.ZERO, BigDecimal::add);
    }
    
    /**
     * Cuenta el total de productos en el carrito
     */
    public Integer getTotalItems() {
        return items.stream()
                   .mapToInt(CartItem::getQuantity)
                   .sum();
    }
    
    /**
     * Verifica si el carrito está vacío
     */
    public boolean isEmpty() {
        return items == null || items.isEmpty();
    }
    
    /**
     * Limpia todo el carrito
     */
    public void clearCart() {
        items.clear();
    }
    
    /**
     * Busca un item por producto
     */
    private CartItem findItemByProduct(Product product) {
        return items.stream()
                   .filter(item -> item.getProduct().getId().equals(product.getId()))
                   .findFirst()
                   .orElse(null);
    }
    
    /**
     * Verifica si un producto está en el carrito
     */
    public boolean containsProduct(Product product) {
        return findItemByProduct(product) != null;
    }
    
    /**
     * Obtiene la cantidad de un producto específico
     */
    public Integer getQuantityOfProduct(Product product) {
        CartItem item = findItemByProduct(product);
        return item != null ? item.getQuantity() : 0;
    }
}