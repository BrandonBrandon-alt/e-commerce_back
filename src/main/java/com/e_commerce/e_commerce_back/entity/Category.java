package com.e_commerce.e_commerce_back.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "categories")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Category {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    // Nombre de la categoría
    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 2, max = 100, message = "El nombre debe tener entre 2 y 100 caracteres")
    @Column(name = "name", nullable = false)
    private String name;
    
    // Slug para URLs amigables
    @NotBlank(message = "El slug es obligatorio")
    @Size(min = 2, max = 100, message = "El slug debe tener entre 2 y 100 caracteres")
    @Column(name = "slug", nullable = false, unique = true)
    private String slug;
    
    // Descripción
    @Size(max = 500, message = "La descripción no puede exceder 500 caracteres")
    @Column(name = "description")
    private String description;
    
    // Categoría padre (para jerarquía)
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private Category parent;
    
    // Subcategorías
    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Category> children = new ArrayList<>();
    
    // Productos en esta categoría
    @ManyToMany(mappedBy = "categories", fetch = FetchType.LAZY)
    private List<Product> products = new ArrayList<>();
    
    // Imagen de la categoría
    @Column(name = "image_url")
    private String imageUrl;
    
    // Icono de la categoría
    @Column(name = "icon")
    private String icon;
    
    // Orden de visualización
    @Column(name = "display_order", nullable = false)
    private Integer displayOrder = 0;
    
    // Nivel en la jerarquía (0 = raíz)
    @Column(name = "level", nullable = false)
    private Integer level = 0;
    
    // Path completo (ej: "hombre/deportivos/running")
    @Column(name = "path")
    private String path;
    
    // Estado
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
    
    @Column(name = "is_featured", nullable = false)
    private boolean isFeatured = false;
    
    // SEO
    @Column(name = "meta_title")
    private String metaTitle;
    
    @Column(name = "meta_description")
    private String metaDescription;
    
    @Column(name = "meta_keywords")
    private String metaKeywords;
    
    // Campos de auditoría
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
    
    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
    
    // Métodos útiles
    
    /**
     * Verifica si es una categoría raíz (sin padre)
     */
    public boolean isRoot() {
        return parent == null;
    }
    
    /**
     * Verifica si es una categoría hoja (sin hijos)
     */
    public boolean isLeaf() {
        return children == null || children.isEmpty();
    }
    
    /**
     * Verifica si tiene subcategorías
     */
    public boolean hasChildren() {
        return children != null && !children.isEmpty();
    }
    
    /**
     * Obtiene el número de subcategorías
     */
    public Integer getChildrenCount() {
        return children != null ? children.size() : 0;
    }
    
    /**
     * Obtiene el número de productos en esta categoría
     */
    public Integer getProductCount() {
        return products != null ? products.size() : 0;
    }
    
    /**
     * Obtiene el número total de productos incluyendo subcategorías
     */
    public Integer getTotalProductCount() {
        int count = getProductCount();
        if (hasChildren()) {
            for (Category child : children) {
                count += child.getTotalProductCount();
            }
        }
        return count;
    }
    
    /**
     * Obtiene la ruta completa de la categoría
     */
    public String getFullPath() {
        if (path != null) return path;
        
        List<String> pathParts = new ArrayList<>();
        
        Category current = this;
        while (current != null) {
            pathParts.add(0, current.getSlug());
            current = current.getParent();
        }
        
        return String.join("/", pathParts);
    }
    
    /**
     * Obtiene el nombre completo con jerarquía
     */
    public String getFullName() {
        List<String> nameParts = new ArrayList<>();
        
        Category current = this;
        while (current != null) {
            nameParts.add(0, current.getName());
            current = current.getParent();
        }
        
        return String.join(" > ", nameParts);
    }
    
    /**
     * Obtiene todas las categorías ancestro
     */
    public List<Category> getAncestors() {
        List<Category> ancestors = new ArrayList<>();
        Category current = this.parent;
        
        while (current != null) {
            ancestors.add(0, current);
            current = current.getParent();
        }
        
        return ancestors;
    }
    
    /**
     * Obtiene todos los descendientes (subcategorías recursivamente)
     */
    public List<Category> getDescendants() {
        List<Category> descendants = new ArrayList<>();
        
        if (hasChildren()) {
            for (Category child : children) {
                descendants.add(child);
                descendants.addAll(child.getDescendants());
            }
        }
        
        return descendants;
    }
    
    /**
     * Verifica si una categoría es ancestro de esta
     */
    public boolean isDescendantOf(Category category) {
        Category current = this.parent;
        
        while (current != null) {
            if (current.getId().equals(category.getId())) {
                return true;
            }
            current = current.getParent();
        }
        
        return false;
    }
    
    /**
     * Actualiza el nivel y path basado en el padre
     */
    public void updateHierarchy() {
        if (parent == null) {
            this.level = 0;
            this.path = this.slug;
        } else {
            this.level = parent.getLevel() + 1;
            this.path = parent.getPath() + "/" + this.slug;
        }
        
        // Actualizar hijos recursivamente
        if (hasChildren()) {
            for (Category child : children) {
                child.updateHierarchy();
            }
        }
    }
    
    /**
     * Obtiene las categorías activas hijas
     */
    public List<Category> getActiveChildren() {
        return children.stream()
                      .filter(Category::isActive)
                      .sorted((c1, c2) -> c1.getDisplayOrder().compareTo(c2.getDisplayOrder()))
                      .toList();
    }
    
    /**
     * Obtiene los productos activos de esta categoría
     */
    public List<Product> getActiveProducts() {
        return products.stream()
                      .filter(Product::isActive)
                      .toList();
    }
    
    /**
     * Verifica si tiene productos activos
     */
    public boolean hasActiveProducts() {
        return products.stream().anyMatch(Product::isActive);
    }
    
    /**
     * Genera el slug automáticamente desde el nombre
     */
    public void generateSlug() {
        if (name != null) {
            this.slug = name.toLowerCase()
                           .replaceAll("[^a-z0-9\\s-]", "")
                           .replaceAll("\\s+", "-")
                           .replaceAll("-+", "-")
                           .trim();
        }
    }
}
