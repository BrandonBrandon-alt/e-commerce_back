package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Promotion;
import com.e_commerce.e_commerce_back.entity.Product;
import com.e_commerce.e_commerce_back.entity.User;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PromotionRepository extends JpaRepository<Promotion, Long> {

    // Buscar por código
    Optional<Promotion> findByCode(String code);
    
    // Verificar si existe un código
    boolean existsByCode(String code);
    
    // Promociones activas
    List<Promotion> findByIsActiveTrueAndStartDateBeforeAndEndDateAfter(LocalDateTime now1, LocalDateTime now2);
    
   
}
