package com.e_commerce.e_commerce_back.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.e_commerce.e_commerce_back.entity.WishlistItem;
import com.e_commerce.e_commerce_back.entity.Wishlist;
import com.e_commerce.e_commerce_back.entity.Product;
import java.util.List;
import java.util.Optional;

@Repository
public interface WishlistItemRepository extends JpaRepository<WishlistItem, Long> {

    // Buscar items por lista
    List<WishlistItem> findByWishlist(Wishlist wishlist);
    
    // Buscar item específico en una lista
    Optional<WishlistItem> findByWishlistAndProduct(Wishlist wishlist, Product product);
    
    // Buscar items por producto (en todas las listas)
    List<WishlistItem> findByProduct(Product product);
    
    // Buscar por prioridad
    List<WishlistItem> findByPriority(WishlistItem.ItemPriority priority);
    
    // Items con notificaciones de precio activadas
    List<WishlistItem> findByNotifyPriceDropTrue();
    
    // Items con notificaciones de stock activadas
    List<WishlistItem> findByNotifyBackInStockTrue();
    
    // Items con talla deseada específica
    List<WishlistItem> findByDesiredSize(Double size);
    
   
}
