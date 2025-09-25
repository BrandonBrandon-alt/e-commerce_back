package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Cart;
import com.e_commerce.e_commerce_back.entity.User;

import java.util.Optional;

@Repository
public interface CartRepository extends JpaRepository<Cart, Long> {

    // Buscar carrito por usuario
    Optional<Cart> findByUser(User user);
    
    // Buscar carrito por ID de usuario
    Optional<Cart> findByUserId(Long userId);
    
    
}
