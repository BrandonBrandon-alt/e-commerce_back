package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.OrderItem;
import com.e_commerce.e_commerce_back.entity.Order;
import com.e_commerce.e_commerce_back.entity.Product;
import java.util.List;

@Repository
public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {

    // Buscar items por orden
    List<OrderItem> findByOrder(Order order);
    
    // Buscar items por producto
    List<OrderItem> findByProduct(Product product);
    
    // Buscar items por talla
    List<OrderItem> findBySize(Double size);
    
    // Buscar items por producto y talla
    List<OrderItem> findByProductAndSize(Product product, Double size);
    
    
}
