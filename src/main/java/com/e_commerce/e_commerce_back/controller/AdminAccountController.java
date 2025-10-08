package com.e_commerce.e_commerce_back.controller;

import com.e_commerce.e_commerce_back.services.implementation.AccountLockoutRedisService;
import com.e_commerce.e_commerce_back.services.implementation.AccountLockoutRedisService.LockoutStatusDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador de administración para gestión de bloqueos de cuenta
 * Solo para desarrollo/testing - En producción debería estar protegido con @PreAuthorize("hasRole('ADMIN')")
 */
@RestController
@RequestMapping("/api/admin/account-lockout")
@RequiredArgsConstructor
@Slf4j
public class AdminAccountController {

    private final AccountLockoutRedisService accountLockoutRedisService;

    /**
     * Obtiene el estado completo de bloqueo de un usuario
     * 
     * GET /api/admin/account-lockout/status/{userId}
     */
    @GetMapping("/status/{userId}")
    public ResponseEntity<LockoutStatusDTO> getLockoutStatus(@PathVariable Long userId) {
        log.info("Consultando estado de bloqueo para usuario: {}", userId);
        
        LockoutStatusDTO status = accountLockoutRedisService.getLockoutStatus(userId);
        
        return ResponseEntity.ok(status);
    }

    /**
     * Desbloquea manualmente una cuenta
     * 
     * POST /api/admin/account-lockout/unlock/{userId}
     */
    @PostMapping("/unlock/{userId}")
    public ResponseEntity<String> unlockAccount(@PathVariable Long userId) {
        log.info("Desbloqueando manualmente cuenta de usuario: {}", userId);
        
        accountLockoutRedisService.unlockAccount(userId);
        
        return ResponseEntity.ok("Cuenta desbloqueada exitosamente");
    }

    /**
     * Limpia todo el historial de bloqueos de un usuario
     * 
     * DELETE /api/admin/account-lockout/history/{userId}
     */
    @DeleteMapping("/history/{userId}")
    public ResponseEntity<String> clearLockoutHistory(@PathVariable Long userId) {
        log.info("Limpiando historial de bloqueos para usuario: {}", userId);
        
        accountLockoutRedisService.clearLockoutHistory(userId);
        
        return ResponseEntity.ok("Historial de bloqueos limpiado");
    }

    /**
     * Limpia TODOS los datos de bloqueo de un usuario (intentos, bloqueo, historial)
     * 
     * DELETE /api/admin/account-lockout/all/{userId}
     */
    @DeleteMapping("/all/{userId}")
    public ResponseEntity<String> clearAllLockoutData(@PathVariable Long userId) {
        log.warn("Limpiando TODOS los datos de bloqueo para usuario: {}", userId);
        
        accountLockoutRedisService.clearAllLockoutData(userId);
        
        return ResponseEntity.ok("Todos los datos de bloqueo eliminados");
    }

    /**
     * Resetea solo los intentos fallidos (sin desbloquear)
     * 
     * POST /api/admin/account-lockout/reset-attempts/{userId}
     */
    @PostMapping("/reset-attempts/{userId}")
    public ResponseEntity<String> resetFailedAttempts(@PathVariable Long userId) {
        log.info("Reseteando intentos fallidos para usuario: {}", userId);
        
        accountLockoutRedisService.resetFailedAttempts(userId);
        
        return ResponseEntity.ok("Intentos fallidos reseteados");
    }
}
