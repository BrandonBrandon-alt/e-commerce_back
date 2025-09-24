package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@MappedSuperclass
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseAuditableEntity {
    
    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    @CreatedBy
    @Column(name = "created_by", length = 100)
    private String createdBy;
    
    @LastModifiedBy
    @Column(name = "last_modified_by", length = 100)
    private String lastModifiedBy;
    
    @Version
    @Column(name = "version")
    private Long version;
    
    @Column(name = "active", nullable = false)
    @Builder.Default
    private Boolean active = true;
    
    // Métodos de ciclo de vida
    @PrePersist
    protected void onCreate() {
        if (active == null) {
            active = true;
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        // Lógica adicional si es necesaria
    }
    
    public void softDelete() {
        this.active = false;
    }
    
    public void restore() {
        this.active = true;
    }
    
    public boolean isDeleted() {
        return !active;
    }
}