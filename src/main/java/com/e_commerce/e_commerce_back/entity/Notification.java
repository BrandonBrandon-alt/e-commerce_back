package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Entidad que representa las notificaciones del sistema para los usuarios
 */
@Entity
@Table(name = "notifications", indexes = {
    @Index(name = "idx_notification_user", columnList = "user_id"),
    @Index(name = "idx_notification_type", columnList = "type"),
    @Index(name = "idx_notification_status", columnList = "status"),
    @Index(name = "idx_notification_created_at", columnList = "created_at"),
    @Index(name = "idx_notification_read_at", columnList = "read_at"),
    @Index(name = "idx_notification_priority", columnList = "priority"),
    @Index(name = "idx_notification_scheduled", columnList = "scheduled_for")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@ToString(exclude = {"user", "relatedProduct", "relatedOrder"})
@EqualsAndHashCode(onlyExplicitlyIncluded = true, callSuper = false)
public class Notification extends BaseAuditableEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    
    @NotNull(message = "notification.validation.user.required")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @NotBlank(message = "notification.validation.title.required")
    @Size(max = 200, message = "notification.validation.title.size")
    @Column(name = "title", nullable = false, length = 200)
    private String title;
    
    @NotBlank(message = "notification.validation.message.required")
    @Size(max = 1000, message = "notification.validation.message.size")
    @Column(name = "message", nullable = false, length = 1000)
    private String message;
    
    @NotNull(message = "notification.validation.type.required")
    @Column(name = "type", nullable = false)
    @Enumerated(EnumType.STRING)
    private NotificationType type;
    
    @NotNull(message = "notification.validation.priority.required")
    @Column(name = "priority", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private NotificationPriority priority = NotificationPriority.MEDIUM;
    
    @NotNull(message = "notification.validation.status.required")
    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private NotificationStatus status = NotificationStatus.PENDING;
    
    @Column(name = "read_at")
    private LocalDateTime readAt;
    
    @Column(name = "clicked_at")
    private LocalDateTime clickedAt;
    
    @Column(name = "scheduled_for")
    private LocalDateTime scheduledFor;
    
    @Column(name = "sent_at")
    private LocalDateTime sentAt;
    
    @Column(name = "failed_at")
    private LocalDateTime failedAt;
    
    @Column(name = "failure_reason", length = 500)
    private String failureReason;
    
    @Column(name = "retry_count", nullable = false)
    @Builder.Default
    private Integer retryCount = 0;
    
    @Column(name = "max_retries", nullable = false)
    @Builder.Default
    private Integer maxRetries = 3;
    
    // Campos para personalización
    @Column(name = "icon", length = 100)
    private String icon;
    
    @Column(name = "image_url", length = 500)
    private String imageUrl;
    
    @Column(name = "action_url", length = 500)
    private String actionUrl;
    
    @Column(name = "action_text", length = 50)
    private String actionText;
    
    // Campos para segmentación
    @Column(name = "channel", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private NotificationChannel channel = NotificationChannel.IN_APP;
    
    @Column(name = "device_type")
    @Enumerated(EnumType.STRING)
    private DeviceType deviceType;
    
    // Relaciones opcionales para contexto
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "related_product_id")
    private Product relatedProduct;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "related_order_id")
    private Order relatedOrder;
    
    @Column(name = "related_entity_type", length = 50)
    private String relatedEntityType;
    
    @Column(name = "related_entity_id")
    private Long relatedEntityId;
    
    // Campos para analytics
    @Column(name = "campaign_id", length = 100)
    private String campaignId;
    
    @Column(name = "tags", length = 500)
    private String tags;
    
    @Column(name = "metadata", length = 1000)
    private String metadata;
    
    // Enums
    public enum NotificationType {
        ORDER_CONFIRMATION("Confirmación de pedido", "🛍️"),
        ORDER_SHIPPED("Pedido enviado", "📦"),
        ORDER_DELIVERED("Pedido entregado", "✅"),
        ORDER_CANCELLED("Pedido cancelado", "❌"),
        PAYMENT_SUCCESS("Pago exitoso", "💳"),
        PAYMENT_FAILED("Pago fallido", "⚠️"),
        PRICE_DROP("Bajada de precio", "💰"),
        BACK_IN_STOCK("Producto disponible", "📦"),
        NEW_PROMOTION("Nueva promoción", "🎉"),
        COUPON_EXPIRING("Cupón por vencer", "⏰"),
        BIRTHDAY_OFFER("Oferta de cumpleaños", "🎂"),
        ABANDONED_CART("Carrito abandonado", "🛒"),
        NEW_REVIEW("Nueva reseña", "⭐"),
        WELCOME("Bienvenida", "👋"),
        ACCOUNT_SECURITY("Seguridad de cuenta", "🔒"),
        SYSTEM_MAINTENANCE("Mantenimiento", "🔧"),
        GENERAL("General", "📢");
        
        private final String displayName;
        private final String emoji;
        
        NotificationType(String displayName, String emoji) {
            this.displayName = displayName;
            this.emoji = emoji;
        }
        
        public String getDisplayName() { return displayName; }
        public String getEmoji() { return emoji; }
        public String getDisplayWithEmoji() { return emoji + " " + displayName; }
    }
    
    public enum NotificationPriority {
        LOW("Baja", 1),
        MEDIUM("Media", 2),
        HIGH("Alta", 3),
        URGENT("Urgente", 4),
        CRITICAL("Crítica", 5);
        
        private final String displayName;
        private final int level;
        
        NotificationPriority(String displayName, int level) {
            this.displayName = displayName;
            this.level = level;
        }
        
        public String getDisplayName() { return displayName; }
        public int getLevel() { return level; }
    }
    
    public enum NotificationStatus {
        PENDING("Pendiente"),
        SCHEDULED("Programada"),
        SENT("Enviada"),
        DELIVERED("Entregada"),
        READ("Leída"),
        CLICKED("Clickeada"),
        FAILED("Fallida"),
        CANCELLED("Cancelada"),
        EXPIRED("Expirada");
        
        private final String displayName;
        
        NotificationStatus(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() { return displayName; }
    }
    
    public enum NotificationChannel {
        IN_APP("En la app"),
        EMAIL("Email"),
        SMS("SMS"),
        PUSH("Push"),
        WHATSAPP("WhatsApp"),
        ALL("Todos los canales");
        
        private final String displayName;
        
        NotificationChannel(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() { return displayName; }
    }
    
    public enum DeviceType {
        WEB("Web"),
        MOBILE("Móvil"),
        TABLET("Tablet"),
        DESKTOP("Escritorio");
        
        private final String displayName;
        
        DeviceType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() { return displayName; }
    }
    
    // Métodos de negocio
    public boolean isRead() {
        return readAt != null;
    }
    
    public boolean isClicked() {
        return clickedAt != null;
    }
    
    public boolean isPending() {
        return status == NotificationStatus.PENDING;
    }
    
    public boolean isSent() {
        return status == NotificationStatus.SENT || status == NotificationStatus.DELIVERED;
    }
    
    public boolean isFailed() {
        return status == NotificationStatus.FAILED;
    }
    
    public boolean isScheduled() {
        return scheduledFor != null && scheduledFor.isAfter(LocalDateTime.now());
    }
    
    public boolean isExpired() {
        return status == NotificationStatus.EXPIRED;
    }
    
    public boolean canRetry() {
        return retryCount < maxRetries && isFailed();
    }
    
    public boolean isHighPriority() {
        return priority == NotificationPriority.HIGH || 
               priority == NotificationPriority.URGENT || 
               priority == NotificationPriority.CRITICAL;
    }
    
    public void markAsRead() {
        if (readAt == null) {
            this.readAt = LocalDateTime.now();
            if (status == NotificationStatus.DELIVERED || status == NotificationStatus.SENT) {
                this.status = NotificationStatus.READ;
            }
        }
    }
    
    public void markAsClicked() {
        if (clickedAt == null) {
            this.clickedAt = LocalDateTime.now();
            if (!isRead()) {
                markAsRead();
            }
            this.status = NotificationStatus.CLICKED;
        }
    }
    
    public void markAsSent() {
        this.sentAt = LocalDateTime.now();
        this.status = NotificationStatus.SENT;
    }
    
    public void markAsDelivered() {
        this.status = NotificationStatus.DELIVERED;
    }
    
    public void markAsFailed(String reason) {
        this.failedAt = LocalDateTime.now();
        this.failureReason = reason;
        this.status = NotificationStatus.FAILED;
        this.retryCount = Objects.requireNonNullElse(this.retryCount, 0) + 1;
    }
    
    public void cancel() {
        this.status = NotificationStatus.CANCELLED;
    }
    
    public void expire() {
        this.status = NotificationStatus.EXPIRED;
    }
    
    public String getFormattedTitle() {
        return type.getEmoji() + " " + title;
    }
    
    public String getPriorityBadge() {
        return switch (priority) {
            case CRITICAL -> "🔴 CRÍTICA";
            case URGENT -> "🟠 URGENTE";
            case HIGH -> "🟡 ALTA";
            case MEDIUM -> "🔵 MEDIA";
            case LOW -> "⚪ BAJA";
        };
    }
    
    public long getMinutesSinceCreated() {
        if (getCreatedAt() == null) return 0;
        return java.time.temporal.ChronoUnit.MINUTES.between(getCreatedAt(), LocalDateTime.now());
    }
    
    public boolean isRecentlyCreated() {
        return getMinutesSinceCreated() <= 60; // Menos de 1 hora
    }
    
    // JPA lifecycle methods
    @PrePersist
    protected void onCreate() {
        super.onCreate();
        if (status == null) {
            status = NotificationStatus.PENDING;
        }
        if (priority == null) {
            priority = NotificationPriority.MEDIUM;
        }
        if (channel == null) {
            channel = NotificationChannel.IN_APP;
        }
        if (retryCount == null) {
            retryCount = 0;
        }
        if (maxRetries == null) {
            maxRetries = 3;
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        super.onUpdate();
    }
}
