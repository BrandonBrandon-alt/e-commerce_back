package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.math.BigDecimal;
@Entity
@Table(name = "product_sizes", 
       uniqueConstraints = @UniqueConstraint(columnNames = {"product_id", "size"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ProductSize {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    @NotNull(message = "La talla es obligatoria")
    @DecimalMin(value = "15.0", message = "Talla mínima: 15")
    @DecimalMax(value = "50.0", message = "Talla máxima: 50")
    @Column(name = "size", nullable = false, precision = 3, scale = 1)
    private BigDecimal size; // Ej: 38.5, 42.0, etc.
    
    @NotNull(message = "El stock es obligatorio")
    @Min(value = 0, message = "El stock no puede ser negativo")
    @Column(name = "stock", nullable = false)
    private Integer stock;
    
    // Métodos útiles
    
    /**
     * Verifica si hay stock disponible
     */
    public boolean hasStock() {
        return stock != null && stock > 0;
    }
    
    /**
     * Verifica si hay suficiente stock para una cantidad
     */
    public boolean hasStock(Integer quantity) {
        return stock != null && stock >= quantity;
    }
    
    /**
     * Reduce el stock en la cantidad especificada
     */
    public void reduceStock(Integer quantity) {
        if (hasStock(quantity)) {
            this.stock -= quantity;
        } else {
            throw new IllegalArgumentException("Stock insuficiente. Disponible: " + stock + ", Solicitado: " + quantity);
        }
    }
    
    /**
     * Aumenta el stock en la cantidad especificada
     */
    public void increaseStock(Integer quantity) {
        this.stock = (this.stock == null ? 0 : this.stock) + quantity;
    }
    
    /**
     * Obtiene la talla como string formateado
     */
    public String getSizeFormatted() {
        if (size == null) return "";
        
        // Si es número entero, mostrar sin decimales
        if (size.compareTo(BigDecimal.valueOf(size.intValue())) == 0) {
            return String.valueOf(size.intValue());
        }
        // Si tiene decimales, mostrarlos
        return String.valueOf(size);
    }
}