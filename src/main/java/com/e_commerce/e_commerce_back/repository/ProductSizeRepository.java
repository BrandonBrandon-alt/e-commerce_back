package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.ProductSize;
import com.e_commerce.e_commerce_back.entity.Product;
import java.util.List;
import java.util.Optional;

@Repository
public interface ProductSizeRepository extends JpaRepository<ProductSize, Long> {

    // Buscar tallas por producto
    List<ProductSize> findByProduct(Product product);
    
    // Buscar tallas por producto ordenadas por talla
    List<ProductSize> findByProductOrderBySizeAsc(Product product);
    
    // Buscar talla específica de un producto
    Optional<ProductSize> findByProductAndSize(Product product, Double size);
    
    // Buscar tallas con stock disponible
    List<ProductSize> findByStockGreaterThan(Integer minStock);
    
    // Buscar tallas con stock disponible por producto
    List<ProductSize> findByProductAndStockGreaterThan(Product product, Integer minStock);
    
    // Buscar tallas sin stock
    List<ProductSize> findByStock(Integer stock);
    
    // Buscar tallas sin stock por producto
    List<ProductSize> findByProductAndStock(Product product, Integer stock);
    
   
}
