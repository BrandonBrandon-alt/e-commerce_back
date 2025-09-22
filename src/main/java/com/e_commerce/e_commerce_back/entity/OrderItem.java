package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.math.BigDecimal;

@Entity
@Table(name = "order_items")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OrderItem {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con Order (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "order_id", nullable = false)
    private Order order;
    
    // Relación con Product (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    // Información del producto al momento de la compra
    @NotNull(message = "El nombre del producto es obligatorio")
    @Column(name = "product_name", nullable = false)
    private String productName;
    
    @Column(name = "product_sku")
    private String productSku;
    
    @Column(name = "product_brand")
    private String productBrand;
    
    @Column(name = "product_color")
    private String productColor;
    
    // Talla específica del producto
    @NotNull(message = "La talla es obligatoria")
    @Column(name = "size", nullable = false, precision = 3, scale = 1)
    private BigDecimal size;
    
    @NotNull(message = "La cantidad es obligatoria")
    @Min(value = 1, message = "La cantidad debe ser al menos 1")
    @Column(name = "quantity", nullable = false)
    private Integer quantity;
    
    // Precio unitario al momento de la compra
    @NotNull(message = "El precio unitario es obligatorio")
    @DecimalMin(value = "0.01", message = "El precio debe ser mayor a 0")
    @Column(name = "unit_price", nullable = false, precision = 10, scale = 2)
    private BigDecimal unitPrice;
    
    // Subtotal calculado (precio unitario × cantidad)
    @NotNull(message = "El subtotal es obligatorio")
    @Column(name = "subtotal", nullable = false, precision = 10, scale = 2)
    private BigDecimal subtotal;
    
    // Métodos útiles
    
    /**
     * Calcula el subtotal basado en precio unitario y cantidad
     */
    public void calculateSubtotal() {
        if (unitPrice != null && quantity != null) {
            this.subtotal = unitPrice.multiply(BigDecimal.valueOf(quantity));
        }
    }
    
    /**
     * Obtiene la talla como string formateado
     */
    public String getSizeFormatted() {
        if (size == null) return "";
        
        // Si es número entero, mostrar sin decimales
        if (size.stripTrailingZeros().scale() <= 0) {
            return String.valueOf(size.intValue());
        }
        // Si tiene decimales, mostrarlos
        return size.toPlainString();
    }
    
    /**
     * Copia la información del producto al momento de la compra
     */
    public void copyProductInfo(Product product) {
        if (product != null) {
            this.productName = product.getName();
            this.productSku = product.getSku();
            this.productBrand = product.getBrand();
            this.productColor = product.getColor();
            this.unitPrice = product.getPrice();
        }
    }
    
    /**
     * Verifica si hay suficiente stock para este item
     */
    public boolean hasAvailableStock() {
        return product != null && product.hasStockForSize(size) && 
               product.getStockForSize(size) >= quantity;
    }
}
