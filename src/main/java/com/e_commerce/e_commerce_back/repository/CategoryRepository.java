package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.Category;
import java.util.List;
import java.util.Optional;

@Repository
public interface CategoryRepository extends JpaRepository<Category, Long> {

    // Buscar por slug
    Optional<Category> findBySlug(String slug);
    
    // Verificar si existe un slug
    boolean existsBySlug(String slug);
    
    // Buscar categorías activas
    List<Category> findByIsActiveTrueOrderByDisplayOrderAsc();
    
    // Buscar categorías raíz (sin padre)
    List<Category> findByParentIsNullAndIsActiveTrueOrderByDisplayOrderAsc();
    
    // Buscar subcategorías de una categoría padre
    List<Category> findByParentAndIsActiveTrueOrderByDisplayOrderAsc(Category parent);
    
    // Buscar por nivel jerárquico
    List<Category> findByLevelAndIsActiveTrue(Integer level);
    
    // Buscar categorías destacadas
    List<Category> findByIsFeaturedTrueAndIsActiveTrueOrderByDisplayOrderAsc();
    
    
}
