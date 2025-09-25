package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Wishlist;
import com.e_commerce.e_commerce_back.entity.User;
import java.util.List;
import java.util.Optional;

@Repository
public interface WishlistRepository extends JpaRepository<Wishlist, Long> {

    // Buscar listas por usuario
    List<Wishlist> findByUserAndIsActiveTrue(User user);
    
    // Buscar lista predeterminada del usuario
    Optional<Wishlist> findByUserAndIsDefaultTrueAndIsActiveTrue(User user);
    
    // Buscar por tipo de lista
    List<Wishlist> findByType(Wishlist.WishlistType type);
    
    // Buscar listas públicas
    List<Wishlist> findByVisibilityAndIsActiveTrue(Wishlist.WishlistVisibility visibility);
    
   
}
