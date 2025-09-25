package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.e_commerce.e_commerce_back.entity.Rating;

public interface RatingRepository extends JpaRepository<Rating, Long> {

    
}