package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entiry.User;

@Repository
public interface AccountRepository extends JpaRepository <User, Long> {

    
}