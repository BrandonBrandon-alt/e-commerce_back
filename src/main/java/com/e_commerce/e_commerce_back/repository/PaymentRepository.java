package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Payment;
import com.e_commerce.e_commerce_back.entity.Order;
import java.util.List;
import java.util.Optional;

@Repository
public interface PaymentRepository extends JpaRepository<Payment, Long> {

    // Buscar por ID de pago
    Optional<Payment> findByPaymentId(String paymentId);
    
    // Buscar por ID de transacción
    Optional<Payment> findByTransactionId(String transactionId);
    
    // Buscar pagos por orden
    List<Payment> findByOrder(Order order);
    
    // Buscar por proveedor de pagos
    List<Payment> findByPaymentProvider(Payment.PaymentProvider provider);
    
    // Buscar por método de pago
    List<Payment> findByPaymentMethod(Payment.PaymentMethod method);
    
    // Buscar por tipo de pago
    List<Payment> findByPaymentType(Payment.PaymentType type);
    
    // Pagos exitosos
    List<Payment> findByStatus(Payment.PaymentStatus status);
    
    // Pagos fallidos
    List<Payment> findByStatusAndFailedAtIsNotNull(Payment.PaymentStatus status);
    
    
}
