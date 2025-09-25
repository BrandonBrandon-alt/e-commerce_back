package com.e_commerce.e_commerce_back.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.e_commerce.e_commerce_back.entity.Product;
import com.e_commerce.e_commerce_back.entity.User;

public interface FavoriteRepository extends JpaRepository<FavoriteRepository, Long> {

    Optional<FavoriteRepository> findByUserAndProduct(User user, Product product);
    

    
}