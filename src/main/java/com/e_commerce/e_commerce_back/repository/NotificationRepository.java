package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.e_commerce.e_commerce_back.entity.Notification;

public interface NotificationRepository extends JpaRepository<Notification, Long> {

    
}