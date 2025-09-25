package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.ReviewImage;
import com.e_commerce.e_commerce_back.entity.Review;
import java.util.List;
import java.util.Optional;

@Repository
public interface ReviewImageRepository extends JpaRepository<ReviewImage, Long> {

    // Buscar imágenes por reseña
    List<ReviewImage> findByReviewAndIsActiveTrueOrderByDisplayOrderAsc(Review review);
    
    // Buscar por URL de imagen
    Optional<ReviewImage> findByImageUrl(String imageUrl);
    
    // Buscar por nombre de archivo
    List<ReviewImage> findByFileName(String fileName);
    
   
}
