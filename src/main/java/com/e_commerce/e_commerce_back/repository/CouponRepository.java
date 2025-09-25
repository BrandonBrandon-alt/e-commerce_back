package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Coupon;
import com.e_commerce.e_commerce_back.entity.User;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface CouponRepository extends JpaRepository<Coupon, Long> {

    // Buscar por código
    Optional<Coupon> findByCode(String code);
    
    // Verificar si existe un código
    boolean existsByCode(String code);
    
    // Cupones activos válidos en este momento
    @Query("SELECT c FROM Coupon c WHERE c.status = 'ACTIVE' AND c.validFrom <= :now AND c.validUntil >= :now")
    List<Coupon> findActiveCoupons(@Param("now") LocalDateTime now);

    // Cupones válidos para un usuario específico
    @Query("SELECT c FROM Coupon c WHERE c.status = 'ACTIVE' AND c.validFrom <= :now AND c.validUntil >= :now AND (c.user IS NULL OR c.user = :user)")
    List<Coupon> findValidCouponsForUser(@Param("user") User user, @Param("now") LocalDateTime now);

    // Cupones que expiran pronto
    @Query("SELECT c FROM Coupon c WHERE c.status = 'ACTIVE' AND c.validUntil BETWEEN :now AND :futureDate")
    List<Coupon> findExpiringSoonCoupons(@Param("now") LocalDateTime now, @Param("futureDate") LocalDateTime futureDate);

    // Cupones por tipo
    List<Coupon> findByType(Coupon.CouponType type);

    // Cupones por estado
    List<Coupon> findByStatus(Coupon.CouponStatus status);

    // Cupones por usuario
    List<Coupon> findByUser(User user);

}
