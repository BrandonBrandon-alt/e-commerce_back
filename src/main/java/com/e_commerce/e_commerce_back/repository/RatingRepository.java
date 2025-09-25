package com.e_commerce.e_commerce_back.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Product;
import com.e_commerce.e_commerce_back.entity.Rating;
import com.e_commerce.e_commerce_back.entity.User;

@Repository
public interface RatingRepository extends JpaRepository<Rating, Long> {

    // Buscar calificación específica por usuario y producto
    Optional<Rating> findByUserAndProduct(User user, Product product);
    
    // Buscar todas las calificaciones de un usuario
    List<Rating> findByUser(User user);
    
    // Buscar calificaciones por producto
    List<Rating> findByProduct(Product product);
    
    // Buscar calificaciones por puntuación
    List<Rating> findByScore(Integer score);
    
    // Calcular promedio de calificaciones por producto
    @Query("SELECT AVG(r.score) FROM Rating r WHERE r.product = :product AND r.moderationStatus = 'APPROVED'")
    Double findAverageScoreByProduct(@Param("product") Product product);
    
    // Contar calificaciones por producto
    @Query("SELECT COUNT(r) FROM Rating r WHERE r.product = :product AND r.moderationStatus = 'APPROVED'")
    long countByProduct(@Param("product") Product product);
    
    // Verificar si un usuario ya calificó un producto
    boolean existsByUserAndProduct(User user, Product product);
}