package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "payments")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Payment {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con Order (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "order_id", nullable = false)
    private Order order;
    
    // ID único del pago
    @NotBlank(message = "El ID del pago es obligatorio")
    @Column(name = "payment_id", nullable = false, unique = true)
    private String paymentId;
    
    // ID de transacción del proveedor de pagos
    @Column(name = "transaction_id")
    private String transactionId;
    
    // Proveedor de pagos
    @Enumerated(EnumType.STRING)
    @Column(name = "payment_provider", nullable = false)
    private PaymentProvider paymentProvider;
    
    // Método de pago
    @Enumerated(EnumType.STRING)
    @Column(name = "payment_method", nullable = false)
    private PaymentMethod paymentMethod;
    
    // Monto del pago
    @NotNull(message = "El monto es obligatorio")
    @DecimalMin(value = "0.01", message = "El monto debe ser mayor a 0")
    @Column(name = "amount", nullable = false, precision = 10, scale = 2)
    private BigDecimal amount;
    
    // Moneda
    @Column(name = "currency", nullable = false)
    private String currency = "MXN";
    
    // Estado del pago
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private PaymentStatus status = PaymentStatus.PENDING;
    
    // Tipo de pago
    @Enumerated(EnumType.STRING)
    @Column(name = "payment_type", nullable = false)
    private PaymentType paymentType = PaymentType.PAYMENT;
    
    // Información de la tarjeta (si aplica)
    @Column(name = "card_last_four")
    private String cardLastFour;
    
    @Column(name = "card_brand")
    private String cardBrand;
    
    @Column(name = "card_exp_month")
    private Integer cardExpMonth;
    
    @Column(name = "card_exp_year")
    private Integer cardExpYear;
    
    // Información adicional
    @Column(name = "gateway_response", length = 1000)
    private String gatewayResponse;
    
    @Column(name = "failure_reason")
    private String failureReason;
    
    @Column(name = "authorization_code")
    private String authorizationCode;
    
    // Fechas importantes
    @Column(name = "processed_at")
    private LocalDateTime processedAt;
    
    @Column(name = "failed_at")
    private LocalDateTime failedAt;
    
    @Column(name = "refunded_at")
    private LocalDateTime refundedAt;
    
    // Información de reembolso
    @Column(name = "refund_amount", precision = 10, scale = 2)
    private BigDecimal refundAmount;
    
    @Column(name = "refund_reason")
    private String refundReason;
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Enums
    public enum PaymentProvider {
        STRIPE("Stripe"),
        PAYPAL("PayPal"),
        MERCADO_PAGO("Mercado Pago"),
        CONEKTA("Conekta"),
        OPENPAY("OpenPay"),
        CLIP("Clip"),
        BANK_TRANSFER("Transferencia Bancaria");
        
        private final String displayName;
        
        PaymentProvider(String displayName) {
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
        CASH_ON_DELIVERY("Pago Contra Entrega"),
        OXXO("OXXO"),
        SPEI("SPEI"),
        WALLET("Monedero Digital");
        
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
        PROCESSING("Procesando"),
        COMPLETED("Completado"),
        FAILED("Fallido"),
        CANCELLED("Cancelado"),
        REFUNDED("Reembolsado"),
        PARTIALLY_REFUNDED("Reembolso Parcial"),
        DISPUTED("En Disputa");
        
        private final String displayName;
        
        PaymentStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum PaymentType {
        PAYMENT("Pago"),
        REFUND("Reembolso"),
        PARTIAL_REFUND("Reembolso Parcial"),
        CHARGEBACK("Contracargo");
        
        private final String displayName;
        
        PaymentType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Verifica si el pago fue exitoso
     */
    public boolean isSuccessful() {
        return status == PaymentStatus.COMPLETED;
    }
    
    /**
     * Verifica si el pago falló
     */
    public boolean isFailed() {
        return status == PaymentStatus.FAILED;
    }
    
    /**
     * Verifica si el pago está pendiente
     */
    public boolean isPending() {
        return status == PaymentStatus.PENDING || status == PaymentStatus.PROCESSING;
    }
    
    /**
     * Verifica si el pago fue reembolsado
     */
    public boolean isRefunded() {
        return status == PaymentStatus.REFUNDED || status == PaymentStatus.PARTIALLY_REFUNDED;
    }
    
    /**
     * Marca el pago como completado
     */
    public void markAsCompleted(String transactionId, String authCode) {
        this.status = PaymentStatus.COMPLETED;
        this.transactionId = transactionId;
        this.authorizationCode = authCode;
        this.processedAt = LocalDateTime.now();
    }
    
    /**
     * Marca el pago como fallido
     */
    public void markAsFailed(String reason) {
        this.status = PaymentStatus.FAILED;
        this.failureReason = reason;
        this.failedAt = LocalDateTime.now();
    }
    
    /**
     * Procesa un reembolso
     */
    public void processRefund(BigDecimal refundAmount, String reason) {
        this.refundAmount = refundAmount;
        this.refundReason = reason;
        this.refundedAt = LocalDateTime.now();
        
        if (refundAmount.compareTo(amount) == 0) {
            this.status = PaymentStatus.REFUNDED;
        } else {
            this.status = PaymentStatus.PARTIALLY_REFUNDED;
        }
    }
    
    /**
     * Obtiene la información de la tarjeta enmascarada
     */
    public String getMaskedCardInfo() {
        if (cardLastFour == null || cardBrand == null) {
            return "N/A";
        }
        return cardBrand + " **** " + cardLastFour;
    }
    
    /**
     * Verifica si es un pago con tarjeta
     */
    public boolean isCardPayment() {
        return paymentMethod == PaymentMethod.CREDIT_CARD || 
               paymentMethod == PaymentMethod.DEBIT_CARD;
    }
    
    /**
     * Obtiene el monto disponible para reembolso
     */
    public BigDecimal getRefundableAmount() {
        if (refundAmount == null) {
            return amount;
        }
        return amount.subtract(refundAmount);
    }
    
    /**
     * Verifica si se puede reembolsar
     */
    public boolean canBeRefunded() {
        return isSuccessful() && getRefundableAmount().compareTo(BigDecimal.ZERO) > 0;
    }
    
    /**
     * Obtiene el porcentaje reembolsado
     */
    public Double getRefundPercentage() {
        if (refundAmount == null || amount.compareTo(BigDecimal.ZERO) == 0) {
            return 0.0;
        }
        return (refundAmount.doubleValue() / amount.doubleValue()) * 100;
    }
}
