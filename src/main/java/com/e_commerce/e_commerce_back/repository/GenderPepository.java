package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.e_commerce.e_commerce_back.entity.Gender;

public interface GenderPepository extends JpaRepository<Gender, Long> {

    
}