package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Review;
import com.e_commerce.e_commerce_back.entity.Product;
import com.e_commerce.e_commerce_back.entity.User;
import java.util.List;
import java.util.Optional;

@Repository
public interface ReviewRepository extends JpaRepository<Review, Long> {

    // Buscar reseñas por producto
    List<Review> findByProduct(Product product);
    
    // Buscar reseñas aprobadas por producto
    List<Review> findByProductAndStatus(Product product, Review.ReviewStatus status);
    
    // Buscar reseñas por usuario
    List<Review> findByUser(User user);
    
    // Buscar reseña específica de usuario para producto
    Optional<Review> findByUserAndProduct(User user, Product product);
    
    // Buscar por calificación
    List<Review> findByRating(Integer rating);
    
    // Buscar reseñas por calificación y producto
    List<Review> findByProductAndRating(Product product, Integer rating);
    
    // Buscar reseñas verificadas
    List<Review> findByVerifiedPurchaseTrue();
    
    // Buscar reseñas pendientes de moderación
    List<Review> findByStatus(Review.ReviewStatus status);
    
   
}
