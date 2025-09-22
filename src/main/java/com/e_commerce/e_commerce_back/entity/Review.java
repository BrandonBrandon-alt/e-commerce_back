package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "reviews", 
       uniqueConstraints = @UniqueConstraint(columnNames = {"user_id", "product_id"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Review {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con User (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    // Relación con Product (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    // Relación con Order (opcional - para verificar que compró el producto)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "order_id")
    private Order order;
    
    // Calificación (1-5 estrellas)
    @NotNull(message = "La calificación es obligatoria")
    @Min(value = 1, message = "La calificación mínima es 1")
    @Max(value = 5, message = "La calificación máxima es 5")
    @Column(name = "rating", nullable = false)
    private Integer rating;
    
    // Título de la reseña
    @Size(max = 100, message = "El título no puede exceder 100 caracteres")
    @Column(name = "title")
    private String title;
    
    // Comentario de la reseña
    @Size(max = 1000, message = "El comentario no puede exceder 1000 caracteres")
    @Column(name = "comment", length = 1000)
    private String comment;
    
    // Talla que compró (para contexto)
    @Column(name = "purchased_size", precision = 3, scale = 1)
    private BigDecimal purchasedSize;
    
    // Estado de la reseña
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private ReviewStatus status = ReviewStatus.PENDING;
    
    // Verificación de compra
    @Column(name = "verified_purchase", nullable = false)
    private boolean verifiedPurchase = false;
    
    // Utilidad de la reseña (votos útiles)
    @Column(name = "helpful_votes", nullable = false)
    private Integer helpfulVotes = 0;
    
    @Column(name = "total_votes", nullable = false)
    private Integer totalVotes = 0;
    
    // Respuesta del vendedor/admin
    @Column(name = "seller_response", length = 500)
    private String sellerResponse;
    
    @Column(name = "seller_response_date")
    private LocalDateTime sellerResponseDate;
    
    // Imágenes de la reseña (opcional)
    @OneToMany(mappedBy = "review", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<ReviewImage> images = new ArrayList<>();
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Enum para estado de la reseña
    public enum ReviewStatus {
        PENDING("Pendiente"),
        APPROVED("Aprobada"),
        REJECTED("Rechazada"),
        HIDDEN("Oculta");
        
        private final String displayName;
        
        ReviewStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Verifica si la reseña está aprobada y visible
     */
    public boolean isVisible() {
        return status == ReviewStatus.APPROVED;
    }
    
    /**
     * Calcula el porcentaje de utilidad de la reseña
     */
    public Double getHelpfulPercentage() {
        if (totalVotes == 0) return 0.0;
        return (helpfulVotes.doubleValue() / totalVotes.doubleValue()) * 100;
    }
    
    /**
     * Agrega un voto útil
     */
    public void addHelpfulVote() {
        this.helpfulVotes++;
        this.totalVotes++;
    }
    
    /**
     * Agrega un voto no útil
     */
    public void addNotHelpfulVote() {
        this.totalVotes++;
    }
    
    /**
     * Obtiene la talla formateada
     */
    public String getPurchasedSizeFormatted() {
        if (purchasedSize == null) return "No especificada";
        
        if (purchasedSize.stripTrailingZeros().scale() <= 0) {
            return String.valueOf(purchasedSize.intValue());
        }
        return purchasedSize.toPlainString();
    }
    
    /**
     * Verifica si la reseña tiene comentario
     */
    public boolean hasComment() {
        return comment != null && !comment.trim().isEmpty();
    }
    
    /**
     * Verifica si la reseña tiene título
     */
    public boolean hasTitle() {
        return title != null && !title.trim().isEmpty();
    }
    
    /**
     * Obtiene el nombre del usuario que escribió la reseña
     */
    public String getReviewerName() {
        if (user != null) {
            return user.getName() + " " + user.getLastName().charAt(0) + ".";
        }
        return "Usuario Anónimo";
    }
    
    /**
     * Verifica si tiene respuesta del vendedor
     */
    public boolean hasSellerResponse() {
        return sellerResponse != null && !sellerResponse.trim().isEmpty();
    }
    
    /**
     * Aprueba la reseña
     */
    public void approve() {
        this.status = ReviewStatus.APPROVED;
    }
    
    /**
     * Rechaza la reseña
     */
    public void reject() {
        this.status = ReviewStatus.REJECTED;
    }
    
    /**
     * Oculta la reseña
     */
    public void hide() {
        this.status = ReviewStatus.HIDDEN;
    }
}
