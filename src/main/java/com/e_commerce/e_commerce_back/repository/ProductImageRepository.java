package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.ProductImage;
import com.e_commerce.e_commerce_back.entity.Product;
import java.util.List;
import java.util.Optional;

@Repository
public interface ProductImageRepository extends JpaRepository<ProductImage, Long> {

    // Buscar imágenes por producto
    List<ProductImage> findByProductAndIsActiveTrueOrderByDisplayOrderAsc(Product product);
    
    // Buscar imagen principal de un producto
    Optional<ProductImage> findByProductAndIsMainTrueAndIsActiveTrue(Product product);
    
    // Buscar por tipo de imagen
    List<ProductImage> findByImageTypeAndIsActiveTrue(ProductImage.ImageType imageType);
    
    // Buscar imágenes por producto y tipo
    List<ProductImage> findByProductAndImageTypeAndIsActiveTrueOrderByDisplayOrderAsc(Product product, 
                                                                                     ProductImage.ImageType imageType);
    
    
}
