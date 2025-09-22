package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.math.BigDecimal;

@Entity
@Table(name = "cart_items", 
       uniqueConstraints = @UniqueConstraint(columnNames = {"cart_id", "product_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CartItem {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con Cart (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cart_id", nullable = false)
    private Cart cart;
    
    // Relación con Product (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    @NotNull(message = "La cantidad es obligatoria")
    @Min(value = 1, message = "La cantidad debe ser al menos 1")
    @Column(name = "quantity", nullable = false)
    private Integer quantity;
    
    // Guardamos el precio del momento para evitar problemas si cambia el precio del producto
    @NotNull(message = "El precio es obligatorio")
    @Column(name = "price", nullable = false, precision = 10, scale = 2)
    private BigDecimal price;
    
    // Métodos útiles
    
    /**
     * Calcula el subtotal de este item (precio × cantidad)
     */
    public BigDecimal getSubtotal() {
        if (price == null || quantity == null) {
            return BigDecimal.ZERO;
        }
        return price.multiply(BigDecimal.valueOf(quantity));
    }
    
    /**
     * Aumenta la cantidad en 1
     */
    public void incrementQuantity() {
        this.quantity = (this.quantity == null ? 0 : this.quantity) + 1;
    }
    
    /**
     * Disminuye la cantidad en 1 (mínimo 1)
     */
    public void decrementQuantity() {
        if (this.quantity != null && this.quantity > 1) {
            this.quantity--;
        }
    }
    
    /**
     * Actualiza el precio con el precio actual del producto
     */
    public void updatePriceFromProduct() {
        if (this.product != null && this.product.getPrice() != null) {
            this.price = this.product.getPrice();
        }
    }
    
}