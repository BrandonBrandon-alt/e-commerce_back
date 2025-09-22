package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "review_images")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ReviewImage {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con Review (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "review_id", nullable = false)
    private Review review;
    
    // URL de la imagen
    @NotBlank(message = "La URL de la imagen es obligatoria")
    @Column(name = "image_url", nullable = false, length = 500)
    private String imageUrl;
    
    // Texto alternativo
    @Size(max = 200, message = "El texto alternativo no puede exceder 200 caracteres")
    @Column(name = "alt_text")
    private String altText;
    
    // Orden de visualización
    @Column(name = "display_order", nullable = false)
    private Integer displayOrder = 0;
    
    // Información del archivo
    @Column(name = "file_name")
    private String fileName;
    
    @Column(name = "file_size")
    private Long fileSize;
    
    @Column(name = "mime_type")
    private String mimeType;
    
    // Estado
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
    
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    // Métodos útiles
    
    /**
     * Obtiene el tamaño formateado
     */
    public String getFormattedFileSize() {
        if (fileSize == null) return "Desconocido";
        
        if (fileSize < 1024) {
            return fileSize + " B";
        } else if (fileSize < 1024 * 1024) {
            return String.format("%.1f KB", fileSize / 1024.0);
        } else {
            return String.format("%.1f MB", fileSize / (1024.0 * 1024.0));
        }
    }
}
