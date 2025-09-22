package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
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
@Table(name = "orders")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Order {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Número de orden único
    @Column(name = "order_number", nullable = false, unique = true)
    private String orderNumber;
    
    // Relación con User (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    // Estado del pedido
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private OrderStatus status = OrderStatus.PENDING;
    
    // Totales
    @NotNull(message = "El subtotal es obligatorio")
    @Column(name = "subtotal", nullable = false, precision = 10, scale = 2)
    private BigDecimal subtotal;
    
    @Column(name = "tax_amount", precision = 10, scale = 2)
    private BigDecimal taxAmount = BigDecimal.ZERO;
    
    @Column(name = "shipping_cost", precision = 10, scale = 2)
    private BigDecimal shippingCost = BigDecimal.ZERO;
    
    @Column(name = "discount_amount", precision = 10, scale = 2)
    private BigDecimal discountAmount = BigDecimal.ZERO;
    
    @NotNull(message = "El total es obligatorio")
    @Column(name = "total_amount", nullable = false, precision = 10, scale = 2)
    private BigDecimal totalAmount;
    
    // Información de envío
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "shipping_address_id")
    private Address shippingAddress;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "billing_address_id")
    private Address billingAddress;
    
    // Método de pago
    @Enumerated(EnumType.STRING)
    @Column(name = "payment_method")
    private PaymentMethod paymentMethod;
    
    @Column(name = "payment_status")
    @Enumerated(EnumType.STRING)
    private PaymentStatus paymentStatus = PaymentStatus.PENDING;
    
    // Items del pedido
    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<OrderItem> orderItems = new ArrayList<>();
    
    // Notas y comentarios
    @Column(name = "notes", length = 500)
    private String notes;
    
    // Fechas importantes
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @Column(name = "shipped_at")
    private LocalDateTime shippedAt;
    
    @Column(name = "delivered_at")
    private LocalDateTime deliveredAt;
    
    @Column(name = "cancelled_at")
    private LocalDateTime cancelledAt;
    
    // Información de tracking
    @Column(name = "tracking_number")
    private String trackingNumber;
    
    @Column(name = "carrier")
    private String carrier;
    
    // Promoción aplicada al pedido (opcional)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "promotion_id")
    private Promotion promotion;
    
    // Enums
    public enum OrderStatus {
        PENDING("Pendiente"),
        CONFIRMED("Confirmado"),
        PROCESSING("Procesando"),
        SHIPPED("Enviado"),
        DELIVERED("Entregado"),
        CANCELLED("Cancelado"),
        RETURNED("Devuelto");
        
        private final String displayName;
        
        OrderStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum PaymentMethod {
        CREDIT_CARD("Tarjeta de Crédito"),
        DEBIT_CARD("Tarjeta de Débito"),
        PAYPAL("PayPal"),
        BANK_TRANSFER("Transferencia Bancaria"),
        CASH_ON_DELIVERY("Pago Contra Entrega");
        
        private final String displayName;
        
        PaymentMethod(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum PaymentStatus {
        PENDING("Pendiente"),
        PAID("Pagado"),
        FAILED("Fallido"),
        REFUNDED("Reembolsado"),
        PARTIALLY_REFUNDED("Reembolso Parcial");
        
        private final String displayName;
        
        PaymentStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Calcula el total del pedido
     */
    public void calculateTotal() {
        this.totalAmount = subtotal
            .add(taxAmount != null ? taxAmount : BigDecimal.ZERO)
            .add(shippingCost != null ? shippingCost : BigDecimal.ZERO)
            .subtract(discountAmount != null ? discountAmount : BigDecimal.ZERO);
    }
    
    /**
     * Verifica si el pedido puede ser cancelado
     */
    public boolean canBeCancelled() {
        return status == OrderStatus.PENDING || status == OrderStatus.CONFIRMED;
    }
    
    /**
     * Verifica si el pedido está completado
     */
    public boolean isCompleted() {
        return status == OrderStatus.DELIVERED;
    }
    
    /**
     * Verifica si el pedido está cancelado
     */
    public boolean isCancelled() {
        return status == OrderStatus.CANCELLED;
    }
    
    /**
     * Marca el pedido como enviado
     */
    public void markAsShipped(String trackingNumber, String carrier) {
        this.status = OrderStatus.SHIPPED;
        this.shippedAt = LocalDateTime.now();
        this.trackingNumber = trackingNumber;
        this.carrier = carrier;
    }
    
    /**
     * Marca el pedido como entregado
     */
    public void markAsDelivered() {
        this.status = OrderStatus.DELIVERED;
        this.deliveredAt = LocalDateTime.now();
    }
    
    /**
     * Cancela el pedido
     */
    public void cancel() {
        this.status = OrderStatus.CANCELLED;
        this.cancelledAt = LocalDateTime.now();
    }
    
    /**
     * Obtiene el número total de items
     */
    public Integer getTotalItems() {
        return orderItems.stream()
                        .mapToInt(OrderItem::getQuantity)
                        .sum();
    }
}
