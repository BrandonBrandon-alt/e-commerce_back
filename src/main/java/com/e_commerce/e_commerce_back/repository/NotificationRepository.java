package com.e_commerce.e_commerce_back.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Notification;
import com.e_commerce.e_commerce_back.entity.User;

@Repository
public interface NotificationRepository extends JpaRepository<Notification, Long> {

    // Buscar notificaciones por usuario
    List<Notification> findByUser(User user);
    
    // Buscar notificaciones no leídas por usuario
    List<Notification> findByUserAndReadAtIsNull(User user);
    
    // Buscar notificaciones por tipo
    List<Notification> findByType(Notification.NotificationType type);
    
    // Buscar notificaciones por estado
    List<Notification> findByStatus(Notification.NotificationStatus status);
    
    // Contar notificaciones no leídas por usuario
    @Query("SELECT COUNT(n) FROM Notification n WHERE n.user = :user AND n.readAt IS NULL")
    long countUnreadByUser(@Param("user") User user);
    
    // Buscar notificaciones pendientes de envío
    @Query("SELECT n FROM Notification n WHERE n.status = 'PENDING'")
    List<Notification> findPendingNotifications();
}
