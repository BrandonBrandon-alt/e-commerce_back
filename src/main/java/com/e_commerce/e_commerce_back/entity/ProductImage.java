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
@Table(name = "product_images")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ProductImage {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Relación con Product (muchos a uno)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private Product product;
    
    // URL de la imagen
    @NotBlank(message = "La URL de la imagen es obligatoria")
    @Column(name = "image_url", nullable = false, length = 500)
    private String imageUrl;
    
    // Texto alternativo para accesibilidad
    @Size(max = 200, message = "El texto alternativo no puede exceder 200 caracteres")
    @Column(name = "alt_text")
    private String altText;
    
    // Orden de visualización
    @Column(name = "display_order", nullable = false)
    private Integer displayOrder = 0;
    
    // Indica si es la imagen principal
    @Column(name = "is_main", nullable = false)
    private boolean isMain = false;
    
    // Tipo de imagen
    @Enumerated(EnumType.STRING)
    @Column(name = "image_type")
    private ImageType imageType = ImageType.PRODUCT;
    
    // Información adicional
    @Column(name = "file_name")
    private String fileName;
    
    @Column(name = "file_size")
    private Long fileSize; // en bytes
    
    @Column(name = "mime_type")
    private String mimeType;
    
    // Dimensiones de la imagen
    @Column(name = "width")
    private Integer width;
    
    @Column(name = "height")
    private Integer height;
    
    // Estado de la imagen
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
    
    // Campo de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    // Enum para tipo de imagen
    public enum ImageType {
        PRODUCT("Producto"),
        THUMBNAIL("Miniatura"),
        GALLERY("Galería"),
        DETAIL("Detalle"),
        ZOOM("Zoom");
        
        private final String displayName;
        
        ImageType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Verifica si la imagen es válida
     */
    public boolean isValid() {
        return imageUrl != null && !imageUrl.trim().isEmpty() && isActive;
    }
    
    /**
     * Obtiene el nombre del archivo desde la URL si no está establecido
     */
    public String getFileNameFromUrl() {
        if (fileName != null && !fileName.trim().isEmpty()) {
            return fileName;
        }
        
        if (imageUrl != null && !imageUrl.trim().isEmpty()) {
            String[] parts = imageUrl.split("/");
            return parts[parts.length - 1];
        }
        
        return null;
    }
    
    /**
     * Verifica si es una imagen de tipo específico
     */
    public boolean isOfType(ImageType type) {
        return this.imageType == type;
    }
    
    /**
     * Marca como imagen principal y actualiza el texto alternativo
     */
    public void setAsMain() {
        this.isMain = true;
        if (this.altText == null || this.altText.trim().isEmpty()) {
            this.altText = product != null ? product.getName() + " - Imagen principal" : "Imagen principal";
        }
    }
    
    /**
     * Remueve el estado de imagen principal
     */
    public void removeAsMain() {
        this.isMain = false;
    }
    
    /**
     * Obtiene el tamaño formateado en KB o MB
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
    
    /**
     * Obtiene las dimensiones formateadas
     */
    public String getFormattedDimensions() {
        if (width != null && height != null) {
            return width + " x " + height + " px";
        }
        return "Desconocido";
    }
    
    /**
     * Verifica si la imagen tiene dimensiones válidas
     */
    public boolean hasValidDimensions() {
        return width != null && height != null && width > 0 && height > 0;
    }
}
