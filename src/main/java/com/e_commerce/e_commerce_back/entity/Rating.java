package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Entidad que representa las calificaciones que los usuarios dan a los productos
 */
@Entity
@Table(name = "ratings", indexes = {
    @Index(name = "idx_rating_user_product", columnList = "user_id, product_id", unique = true),
    @Index(name = "idx_rating_product", columnList = "product_id"),
    @Index(name = "idx_rating_score", columnList = "score"),
    @Index(name = "idx_rating_created_at", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@ToString(exclude = {"user", "product"})
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
public class Rating extends BaseAuditableEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @NotNull(message = "rating.validation.user.required")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @NotNull(message = "rating.validation.product.required")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    @NotNull(message = "rating.validation.score.required")
    @Min(value = 1, message = "rating.validation.score.min")
    @Max(value = 5, message = "rating.validation.score.max")
    @Column(name = "score", nullable = false)
    private Integer score;
    
    @Size(max = 1000, message = "rating.validation.comment.size")
    @Column(name = "comment", length = 1000)
    private String comment;
    
    @Column(name = "is_verified_purchase", nullable = false)
    @Builder.Default
    private Boolean isVerifiedPurchase = false;
    
    @Column(name = "helpful_votes", nullable = false)
    @Builder.Default
    private Integer helpfulVotes = 0;
    
    @Column(name = "total_votes", nullable = false)
    @Builder.Default
    private Integer totalVotes = 0;
    
    @Column(name = "is_featured", nullable = false)
    @Builder.Default
    private Boolean isFeatured = false;
    
    @Column(name = "moderation_status", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private ModerationStatus moderationStatus = ModerationStatus.PENDING;
    
    @Column(name = "moderated_at")
    private LocalDateTime moderatedAt;
    
    @Column(name = "moderated_by")
    private String moderatedBy;
    
    // Enum para estado de moderación
    public enum ModerationStatus {
        PENDING("Pendiente"),
        APPROVED("Aprobado"),
        REJECTED("Rechazado"),
        FLAGGED("Marcado");
        
        private final String displayName;
        
        ModerationStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos de negocio
    public Double getHelpfulnessRatio() {
        if (totalVotes == null || totalVotes == 0) {
            return 0.0;
        }
        return (double) Objects.requireNonNullElse(helpfulVotes, 0) / totalVotes;
    }
    
    public boolean isHighlyRated() {
        return score != null && score >= 4;
    }
    
    public boolean isLowRated() {
        return score != null && score <= 2;
    }
    
    public boolean hasComment() {
        return comment != null && !comment.trim().isEmpty();
    }
    
    public boolean isApproved() {
        return moderationStatus == ModerationStatus.APPROVED;
    }
    
    public boolean isPending() {
        return moderationStatus == ModerationStatus.PENDING;
    }
    
    public boolean isRejected() {
        return moderationStatus == ModerationStatus.REJECTED;
    }
    
    public void approve(String moderatorName) {
        this.moderationStatus = ModerationStatus.APPROVED;
        this.moderatedAt = LocalDateTime.now();
        this.moderatedBy = moderatorName;
    }
    
    public void reject(String moderatorName) {
        this.moderationStatus = ModerationStatus.REJECTED;
        this.moderatedAt = LocalDateTime.now();
        this.moderatedBy = moderatorName;
    }
    
    public void flag(String moderatorName) {
        this.moderationStatus = ModerationStatus.FLAGGED;
        this.moderatedAt = LocalDateTime.now();
        this.moderatedBy = moderatorName;
    }
    
    public void addHelpfulVote() {
        this.helpfulVotes = Objects.requireNonNullElse(this.helpfulVotes, 0) + 1;
        this.totalVotes = Objects.requireNonNullElse(this.totalVotes, 0) + 1;
    }
    
    public void addUnhelpfulVote() {
        this.totalVotes = Objects.requireNonNullElse(this.totalVotes, 0) + 1;
    }
    
    public String getScoreDescription() {
        if (score == null) return "Sin calificación";
        
        return switch (score) {
            case 1 -> "⭐ Muy malo";
            case 2 -> "⭐⭐ Malo";
            case 3 -> "⭐⭐⭐ Regular";
            case 4 -> "⭐⭐⭐⭐ Bueno";
            case 5 -> "⭐⭐⭐⭐⭐ Excelente";
            default -> "Calificación inválida";
        };
    }
    
    // JPA lifecycle methods
    @PrePersist
    protected void onCreate() {
        super.onCreate();
        if (moderationStatus == null) {
            moderationStatus = ModerationStatus.PENDING;
        }
        if (isVerifiedPurchase == null) {
            isVerifiedPurchase = false;
        }
        if (helpfulVotes == null) {
            helpfulVotes = 0;
        }
        if (totalVotes == null) {
            totalVotes = 0;
        }
        if (isFeatured == null) {
            isFeatured = false;
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        super.onUpdate();
    }
}
