package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Address;
import com.e_commerce.e_commerce_back.entity.User;
import java.util.List;
import java.util.Optional;

@Repository
public interface AddressRepository extends JpaRepository<Address, Long> {

    // Buscar direcciones por usuario
    List<Address> findByUser(User user);
    
    // Buscar direcciones activas por usuario
    List<Address> findByUserAndIsActiveTrue(User user);
    
    // Buscar dirección predeterminada del usuario
    Optional<Address> findByUserAndIsDefaultTrue(User user);
    
    // Buscar por tipo de dirección
    List<Address> findByUserAndType(User user, Address.AddressType type);
    
    // Buscar por ciudad
    List<Address> findByCity(String city);
    
    // Buscar por estado
    List<Address> findByState(String state);
    
    // Buscar por código postal
    List<Address> findByPostalCode(String postalCode);
    
    // Buscar por país
    List<Address> findByCountry(String country);
    
    // Buscar direcciones por ciudad y estado
    List<Address> findByCityAndState(String city, String state);
    
   
}
