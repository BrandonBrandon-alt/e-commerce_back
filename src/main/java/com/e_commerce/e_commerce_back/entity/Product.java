package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
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
@Table(name = "products")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Product {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 3, max = 100)
    @Column(name = "name", nullable = false)
    private String name;
    
    @Column(name = "description", length = 1000)
    private String description;
    
    @NotNull(message = "El precio es obligatorio")
    @DecimalMin(value = "0.01", message = "El precio debe ser mayor a 0")
    @Column(name = "price", nullable = false, precision = 10, scale = 2)
    private BigDecimal price;
    
    // Campos específicos para zapatos
    @NotBlank(message = "La marca es obligatoria")
    @Column(name = "brand", nullable = false)
    private String brand;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "gender", nullable = false)
    private Gender gender;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false)
    private ShoeCategory category;
    
    @NotBlank(message = "El color es obligatorio")
    @Column(name = "color", nullable = false)
    private String color;
    
    @Column(name = "material")
    private String material;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "shoe_type", nullable = false)
    private ShoeType shoeType;
    
    // Tallas y stock
    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<ProductSize> sizes = new ArrayList<>();
    
    // Imágenes del producto
    @OneToMany(mappedBy = "product", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<ProductImage> images = new ArrayList<>();
    
    // Categorías del producto (relación muchos a muchos)
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
        name = "product_categories",
        joinColumns = @JoinColumn(name = "product_id"),
        inverseJoinColumns = @JoinColumn(name = "category_id")
    )
    private List<Category> categories = new ArrayList<>();
    
    // SKU único para cada producto
    @NotBlank(message = "El SKU es obligatorio")
    @Column(name = "sku", nullable = false, unique = true)
    private String sku;
    
    // Estado del producto
    @Column(name = "active", nullable = false)
    private boolean active = true;
    
    @Column(name = "featured", nullable = false)
    private boolean featured = false;
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Nota: El enum Gender ahora está en una clase separada para reutilización
    
    public enum ShoeCategory {
        DEPORTIVOS("Deportivos"),
        FORMALES("Formales"),
        CASUALES("Casuales"),
        BOTAS("Botas"),
        SANDALIAS("Sandalias"),
        ZAPATILLAS("Zapatillas"),
        TACONES("Tacones");
        
        private final String displayName;
        
        ShoeCategory(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    public enum ShoeType {
        RUNNING("Running"),
        BASKETBALL("Basketball"),
        FUTBOL("Fútbol"),
        TENIS("Tenis"),
        OXFORD("Oxford"),
        LOAFER("Loafer"),
        SNEAKER("Sneaker"),
        BOOT("Bota"),
        SANDAL("Sandalia"),
        HIGH_HEEL("Tacón Alto"),
        FLAT("Zapato Plano");
        
        private final String displayName;
        
        ShoeType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    // Métodos útiles
    
    /**
     * Verifica si el producto tiene stock en alguna talla
     */
    public boolean hasStock() {
        return sizes.stream().anyMatch(size -> size.getStock() > 0);
    }
    
    /**
     * Obtiene el stock total de todas las tallas
     */
    public Integer getTotalStock() {
        return sizes.stream()
                   .mapToInt(ProductSize::getStock)
                   .sum();
    }
    
    /**
     * Verifica si hay stock disponible para una talla específica
     */
    public boolean hasStockForSize(BigDecimal size) {
        return sizes.stream()
                   .anyMatch(ps -> ps.getSize().equals(size) && ps.getStock() > 0);
    }
    
    /**
     * Obtiene el stock de una talla específica
     */
    public Integer getStockForSize(BigDecimal size) {
        return sizes.stream()
                   .filter(ps -> ps.getSize().equals(size))
                   .mapToInt(ProductSize::getStock)
                   .findFirst()
                   .orElse(0);
    }
    
    /**
     * Obtiene la imagen principal del producto
     */
    public String getMainImageUrl() {
        return images.stream()
                    .filter(ProductImage::isMain)
                    .map(ProductImage::getImageUrl)
                    .findFirst()
                    .orElse(null);
    }
    
    /**
     * Obtiene todas las tallas disponibles (con stock > 0)
     */
    public List<BigDecimal> getAvailableSizes() {
        return sizes.stream()
                   .filter(ps -> ps.getStock() > 0)
                   .map(ProductSize::getSize)
                   .sorted()
                   .toList();
    }
    
    /**
     * Verifica si el producto está disponible para la venta
     */
    public boolean isAvailable() {
        return active && hasStock();
    }
    
    /**
     * Reduce el stock de una talla específica
     */
    public void reduceStock(BigDecimal size, Integer quantity) {
        sizes.stream()
              .filter(ps -> ps.getSize().equals(size))
              .findFirst()
              .ifPresent(ps -> ps.reduceStock(quantity));
    }
    
    /**
     * Aumenta el stock de una talla específica
     */
    public void increaseStock(BigDecimal size, Integer quantity) {
        sizes.stream()
              .filter(ps -> ps.getSize().equals(size))
              .findFirst()
              .ifPresent(ps -> ps.increaseStock(quantity));
    }
}