package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Role;
import com.e_commerce.e_commerce_back.entity.User;
import java.util.Optional;
import java.util.List;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // Buscar por email
    Optional<User> findByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.idNumber = :id_number")
    Optional<User> findByIdNumber(@Param("id_number") String idNumber);
    
    
    // Verificar si existe un email
    boolean existsByEmail(String email);
    
    // Buscar por token de verificación
    Optional<User> findByVerificationToken(String token);
    
    // Buscar por token de reset de password
    Optional<User> findByResetPasswordToken(String token);
    
    // Buscar usuarios activos
    List<User> findByEnabledTrue();
    
    // Buscar por rol
    List<User> findByRole(Role role);
    
    // Buscar usuarios con email verificado
    List<User> findByEmailVerifiedTrue();
    
  
}
