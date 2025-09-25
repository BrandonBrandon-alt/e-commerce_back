package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Coupon;
import java.util.List;
import java.util.Optional;
import java.time.LocalDateTime;

@Repository
public interface CoupunRepository extends JpaRepository<Coupon, Long> {

    // Buscar por código
    Optional<Coupon> findByCode(String code);
    
    // Verificar si existe un código
    boolean existsByCode(String code);
    
    // Coupuns activos
    List<Coupon> findByIsActiveTrueAndStartDateBeforeAndEndDateAfter(LocalDateTime now1, LocalDateTime now2);
    
   
}