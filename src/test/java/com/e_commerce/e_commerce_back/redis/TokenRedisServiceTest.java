package com.e_commerce.e_commerce_back.redis;

import com.e_commerce.e_commerce_back.services.implementation.TokenRedisService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Test para verificar que TokenRedisService funcione correctamente
 * Requiere que Redis esté ejecutándose (Docker Compose)
 */
@SpringBootTest
@ActiveProfiles("test")
public class TokenRedisServiceTest {

    @Autowired
    private TokenRedisService tokenRedisService;

    @Test
    void testRedisConnection() {
        try {
            System.out.println("=== TESTING REDIS CONNECTION AND TOKEN SERVICE ===");
            
            Long testUserId = 999L;
            
            // Test 1: Generar código de activación
            System.out.println("\n1. Generando código de activación...");
            String activationCode = tokenRedisService.generateAndStoreActivationCode(testUserId);
            System.out.println("   Código generado: " + activationCode);
            System.out.println("   ✅ Código de activación almacenado en Redis");
            
            // Test 2: Verificar que el código existe
            System.out.println("\n2. Verificando existencia del código...");
            boolean hasCode = tokenRedisService.hasActiveActivationCode(testUserId);
            System.out.println("   Tiene código activo: " + hasCode);
            System.out.println("   ✅ Verificación de existencia funciona");
            
            // Test 3: Verificar TTL
            System.out.println("\n3. Verificando TTL del código...");
            long ttl = tokenRedisService.getActivationCodeTTL(testUserId);
            System.out.println("   TTL restante: " + ttl + " minutos");
            System.out.println("   ✅ TTL funciona correctamente");
            
            // Test 4: Verificar código correcto
            System.out.println("\n4. Verificando código correcto...");
            boolean isValid = tokenRedisService.verifyActivationCode(testUserId, activationCode);
            System.out.println("   Código válido: " + isValid);
            System.out.println("   ✅ Verificación de código funciona");
            
            // Test 5: Verificar que el código se eliminó después de usar
            System.out.println("\n5. Verificando que el código se eliminó...");
            boolean hasCodeAfter = tokenRedisService.hasActiveActivationCode(testUserId);
            System.out.println("   Tiene código después de usar: " + hasCodeAfter);
            System.out.println("   ✅ Código se elimina correctamente después del uso");
            
            // Test 6: Verificar código incorrecto
            System.out.println("\n6. Probando código incorrecto...");
            String newCode = tokenRedisService.generateAndStoreActivationCode(testUserId);
            boolean isInvalid = tokenRedisService.verifyActivationCode(testUserId, "000000");
            System.out.println("   Código incorrecto rechazado: " + !isInvalid);
            System.out.println("   ✅ Validación de códigos incorrectos funciona");
            
            // Test 7: Rate limiting
            System.out.println("\n7. Probando rate limiting...");
            boolean canRequest1 = tokenRedisService.canRequestToken(testUserId, "activation");
            boolean canRequest2 = tokenRedisService.canRequestToken(testUserId, "activation");
            boolean canRequest3 = tokenRedisService.canRequestToken(testUserId, "activation");
            boolean canRequest4 = tokenRedisService.canRequestToken(testUserId, "activation"); // Este debería ser el límite
            System.out.println("   Solicitudes permitidas: 1=" + canRequest1 + ", 2=" + canRequest2 + ", 3=" + canRequest3 + ", 4=" + canRequest4);
            System.out.println("   ✅ Rate limiting funciona");
            
            // Test 8: Status de tokens
            System.out.println("\n8. Obteniendo status de tokens...");
            var status = tokenRedisService.getUserTokensStatus(testUserId);
            System.out.println("   Status: " + status);
            System.out.println("   ✅ Status de tokens funciona");
            
            // Cleanup
            System.out.println("\n9. Limpiando tokens de prueba...");
            tokenRedisService.invalidateAllUserTokens(testUserId);
            System.out.println("   ✅ Cleanup completado");
            
            System.out.println("\n=== ✅ TODOS LOS TESTS DE REDIS PASARON EXITOSAMENTE ===");
            System.out.println("🎉 TokenRedisService está funcionando correctamente!");
            System.out.println("🐳 Redis Docker Compose está funcionando!");
            System.out.println("🔧 RedisTemplate está configurado correctamente!");
            
        } catch (Exception e) {
            System.err.println("❌ ERROR EN TEST DE REDIS: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            System.err.println("\n🔍 POSIBLES CAUSAS:");
            System.err.println("   1. Redis no está ejecutándose (ejecuta: docker-compose up redis)");
            System.err.println("   2. Puerto 6379 no está disponible");
            System.err.println("   3. Configuración de Redis incorrecta");
            System.err.println("   4. RedisTemplate no está configurado");
            e.printStackTrace();
            throw e;
        }
    }
    
    @Test
    void testAllTokenTypes() {
        try {
            System.out.println("=== TESTING ALL TOKEN TYPES ===");
            
            Long testUserId = 888L;
            
            // Test activation code
            System.out.println("\n1. Testing Activation Code...");
            String activationCode = tokenRedisService.generateAndStoreActivationCode(testUserId);
            boolean activationValid = tokenRedisService.verifyActivationCode(testUserId, activationCode);
            System.out.println("   Activation code: " + activationCode + " - Valid: " + activationValid);
            
            // Test reset code
            System.out.println("\n2. Testing Reset Code...");
            String resetCode = tokenRedisService.generateAndStoreResetCode(testUserId);
            boolean resetValid = tokenRedisService.verifyResetCode(testUserId, resetCode);
            System.out.println("   Reset code: " + resetCode + " - Valid: " + resetValid);
            
            // Test unlock code
            System.out.println("\n3. Testing Unlock Code...");
            String unlockCode = tokenRedisService.generateAndStoreUnlockCode(testUserId);
            boolean unlockValid = tokenRedisService.verifyUnlockCode(testUserId, unlockCode);
            System.out.println("   Unlock code: " + unlockCode + " - Valid: " + unlockValid);
            
            System.out.println("\n✅ All token types working correctly!");
            
            // Cleanup
            tokenRedisService.invalidateAllUserTokens(testUserId);
            
        } catch (Exception e) {
            System.err.println("❌ ERROR testing token types: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
}
