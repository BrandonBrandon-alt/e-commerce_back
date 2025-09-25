package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Order;
import com.e_commerce.e_commerce_back.entity.User;
import java.util.List;
import java.util.Optional;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

    // Buscar por número de orden
    Optional<Order> findByOrderNumber(String orderNumber);
    
    // Buscar órdenes por usuario
    List<Order> findByUserOrderByCreatedAtDesc(User user);
    
    // Buscar órdenes por usuario con paginación
    Page<Order> findByUser(User user, Pageable pageable);
    
    // Buscar por estado
    List<Order> findByStatus(Order.OrderStatus status);
    
    // Buscar por estado de pago
    List<Order> findByPaymentStatus(Order.PaymentStatus paymentStatus);
    
    // Buscar por método de pago
    List<Order> findByPaymentMethod(Order.PaymentMethod paymentMethod);
    
   
}
