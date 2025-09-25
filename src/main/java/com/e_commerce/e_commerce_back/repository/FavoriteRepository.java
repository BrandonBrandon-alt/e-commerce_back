package com.e_commerce.e_commerce_back.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Favorite;
import com.e_commerce.e_commerce_back.entity.Product;
import com.e_commerce.e_commerce_back.entity.User;

@Repository
public interface FavoriteRepository extends JpaRepository<Favorite, Long> {

    // Buscar favorito específico por usuario y producto
    Optional<Favorite> findByUserAndProduct(User user, Product product);
    
    // Buscar todos los favoritos de un usuario
    List<Favorite> findByUser(User user);
    
    // Buscar favoritos por producto
    List<Favorite> findByProduct(Product product);
    
    // Verificar si un producto es favorito de un usuario
    boolean existsByUserAndProduct(User user, Product product);
}