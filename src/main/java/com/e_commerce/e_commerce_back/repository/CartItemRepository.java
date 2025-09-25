package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.CartItem;
import com.e_commerce.e_commerce_back.entity.Cart;
import com.e_commerce.e_commerce_back.entity.Product;
import java.util.List;
import java.util.Optional;

@Repository
public interface CartItemRepository extends JpaRepository<CartItem, Long> {

    // Buscar items por carrito
    List<CartItem> findByCart(Cart cart);
    
    // Buscar item específico en un carrito
    Optional<CartItem> findByCartAndProduct(Cart cart, Product product);
    
    // Buscar items por producto (para análisis)
    List<CartItem> findByProduct(Product product);
    
   
}
