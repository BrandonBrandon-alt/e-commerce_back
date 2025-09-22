package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Product;
import com.e_commerce.e_commerce_back.entity.Gender;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {

    // Buscar productos activos
    List<Product> findByActiveTrue();
    
    // Buscar productos destacados
    List<Product> findByFeaturedTrueAndActiveTrue();
    
    // Buscar por SKU
    Optional<Product> findBySku(String sku);
    
    // Buscar por marca
    List<Product> findByBrandAndActiveTrue(String brand);
    
    // Buscar por género
    List<Product> findByGenderAndActiveTrue(Gender gender);
    
    // Buscar por categoría
    List<Product> findByCategoryAndActiveTrue(Product.ShoeCategory category);
    
    // Buscar por tipo de zapato
    List<Product> findByShoeTypeAndActiveTrue(Product.ShoeType shoeType);
    
    // Buscar por color
    List<Product> findByColorContainingIgnoreCaseAndActiveTrue(String color);
    
   
}
