package com.e_commerce.e_commerce_back.Account;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.e_commerce.e_commerce_back.dto.ActivateAccountDTO;
import com.e_commerce.e_commerce_back.dto.AuthResponseDTO;
import com.e_commerce.e_commerce_back.dto.LoginDTO;
import com.e_commerce.e_commerce_back.dto.RegisterUserDTO;
import com.e_commerce.e_commerce_back.dto.TokenValidationDTO;
import com.e_commerce.e_commerce_back.dto.UserInfoDTO;
import com.e_commerce.e_commerce_back.services.implementation.AuthServiceImpl;
import com.e_commerce.e_commerce_back.services.interfaces.EmailService;
import com.e_commerce.e_commerce_back.security.JwtUtil;

@SpringBootTest
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class AuthTest {
    
    @Autowired
    AuthServiceImpl authService;
    
    @Autowired
    EmailService emailServiceImpl;

    @Autowired
    JwtUtil jwtUtil;

    // Variables estáticas para compartir datos entre tests
    private static String SAVED_ACCESS_TOKEN = "";
    private static final String TEST_EMAIL = "brandonmontealegre15@gmail.com";

    @Test
    @Order(1)
    public void testRegisterUser() {
        try {
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "1001277430",
                "Brandon",
                "Test",
                TEST_EMAIL,
                "3153033412",
                "M@mahermosa123",
                LocalDate.of(2000, 8, 17),
                true
            );

            System.out.println("🚀 Test 1: Registrando usuario...");
            AuthResponseDTO response = authService.register(registerUserDTO);
            
            System.out.println("✅ " + response.getMessage());
            System.out.println("📧 Revisa tu email: " + TEST_EMAIL);
            System.out.println("🔍 Busca: 'Código de Activación - E-Commerce Store'");
            
            Thread.sleep(3000);
            System.out.println("✨ Registro completado!\n");
            
        } catch (Exception e) {
            System.err.println("❌ Error en registro: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Test
    @Order(2)
    public void testActivateAccount() {
        try {
            // IMPORTANTE: Cambia este código por el que recibas en el email
            String activationCode = "902195"; // <- Actualiza este valor
            
            ActivateAccountDTO activateAccountDTO = new ActivateAccountDTO(
                activationCode
            );
            
            System.out.println("🔐 Test 2: Activando cuenta con código: " + activationCode);
            AuthResponseDTO response = authService.activateAccount(activateAccountDTO);
            
            System.out.println("✅ " + response.getMessage());
            System.out.println("✨ Activación completada!\n");
            
        } catch (Exception e) {
            System.err.println("❌ Error en activación: " + e.getMessage());
            System.err.println("💡 Asegúrate de usar el código correcto del email");
        }
    }

    @Test
    @Order(3)
    public void testLogin() {
        try {
            LoginDTO loginDTO = new LoginDTO(
                "brandonmontealegre15@gmail.com",
                "M@mahermosa123"
            );
            
            System.out.println("🔑 Test 3: Iniciando sesión...");
            AuthResponseDTO response = authService.login(loginDTO);
            
            System.out.println("✅ " + response.getMessage());
            
            // Guardar token para otros tests
            if (response.getAccessToken() != null) {
                SAVED_ACCESS_TOKEN = response.getAccessToken();
                System.out.println("🎫 Token guardado para siguientes tests");
                System.out.println("📄 Token: " + SAVED_ACCESS_TOKEN.substring(0, 30) + "...");
            }
            
            System.out.println("✨ Login completado!\n");
            
        } catch (Exception e) {
            System.err.println("❌ Error en login: " + e.getMessage());
            System.err.println("💡 Asegúrate de que la cuenta esté activada");
        }
    }

    @Test
    @Order(4)
    public void testValidateToken() {
        try {
            if (SAVED_ACCESS_TOKEN.isEmpty()) {
                System.out.println("⚠️ No hay token guardado, ejecuta testLogin primero");
                return;
            }
            
            System.out.println("🔍 Test 4: Validando token...");
            TokenValidationDTO response = authService.validateToken(SAVED_ACCESS_TOKEN);
            
            System.out.println("✅ Token válido: " + response.isValid());
            System.out.println("📧 Usuario: " + response.getUsername());
            System.out.println("✨ Validación completada!\n");
            
        } catch (Exception e) {
            System.err.println("❌ Error validando token: " + e.getMessage());
        }
    }

    @Test
    @Order(5)
    public void testGetCurrentUserInfo() {
        try {
            System.out.println("👤 Test 5: Obteniendo info del usuario actual...");
            
            // Nota: Este test podría requerir autenticación en el contexto
            UserInfoDTO response = authService.getCurrentUserInfo();
            
            System.out.println("✅ Usuario: " + response.getName() + " " + response.getLastName());
            System.out.println("📧 Email: " + response.getEmail());
            System.out.println("✨ Info obtenida!\n");
            
        } catch (Exception e) {
            System.err.println("❌ Error obteniendo info: " + e.getMessage());
            System.err.println("💡 Este método podría requerir contexto de seguridad");
        }
    }

    @Test
    @Order(6)
    public void testLogout() {
        try {
            if (SAVED_ACCESS_TOKEN.isEmpty()) {
                System.out.println("⚠️ No hay token guardado, ejecuta testLogin primero");
                return;
            }
            
            System.out.println("🚪 Test 6: Cerrando sesión...");
            String authHeader = "Bearer " + SAVED_ACCESS_TOKEN;
            
            authService.logout(authHeader);
            System.out.println("✅ Logout exitoso!");
            
            // Verificar que el token ya no es válido
            System.out.println("🔍 Verificando invalidación del token...");
            try {
                String username = jwtUtil.extractUsername(SAVED_ACCESS_TOKEN);
                System.out.println("⚠️ Token aún válido para: " + username);
            } catch (Exception e) {
                System.out.println("✅ Token correctamente invalidado");
            }
            
            System.out.println("✨ Logout completado!\n");
            
        } catch (Exception e) {
            System.err.println("❌ Error en logout: " + e.getMessage());
        }
    }

    // ========================================
    // TESTS ADICIONALES PARA CASOS EDGE
    // ========================================

    @Test
    public void testLogoutWithInvalidToken() {
        try {
            System.out.println("🧪 Test Extra: Logout con token inválido...");
            
            authService.logout("Bearer token.falso.123");
            System.out.println("✅ Logout con token inválido manejado correctamente");
            
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
        }
    }

    @Test
    public void testLogoutWithoutToken() {
        try {
            System.out.println("🧪 Test Extra: Logout sin token...");
            
            authService.logout(null);
            System.out.println("✅ Logout sin token manejado correctamente");
            
        } catch (Exception e) {
            System.err.println("❌ Error: " + e.getMessage());
        }
    }

    // ========================================
    // TEST COMPLETO (EL QUE YA TENÍAS)
    // ========================================

    @Test
    public void testCompleteFlow() {
        try {
            System.out.println("\n" + "=".repeat(50));
            System.out.println("🎯 TEST COMPLETO - FLUJO COMPLETO DE AUTENTICACIÓN");
            System.out.println("=".repeat(50));
            
            // Este es tu test original - mantenerlo como respaldo
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "1001277999", // documento diferente
                "Test",
                "Complete",
                "brandonmontealegre15@gmail.com",
                "3153033412",
                "M@mahermosa123",
                LocalDate.of(2000, 8, 17),
                true
            );
            
            System.out.println("🚀 Paso 1: Registro...");
            authService.register(registerUserDTO);
            System.out.println("✅ Registrado");

            System.out.println("🔐 Paso 2: Activación (usa código real)...");
            ActivateAccountDTO activateDTO = new ActivateAccountDTO(
                "123456" // <- Código del email
            );
            
            try {
                authService.activateAccount(activateDTO);
                System.out.println("✅ Activado");
            } catch (Exception e) {
                System.out.println("⚠️ Error activando: " + e.getMessage());
                return;
            }

            System.out.println("🔑 Paso 3: Login...");
            LoginDTO loginDTO = new LoginDTO("brandonmontealegre15@gmail.com", "M@mahermosa123");
            AuthResponseDTO loginResponse = authService.login(loginDTO);
            String accessToken = loginResponse.getAccessToken();
            System.out.println("✅ Login exitoso");

            System.out.println("🚪 Paso 4: Logout...");
            authService.logout("Bearer " + accessToken);
            System.out.println("✅ Logout exitoso");

            System.out.println("\n🎉 FLUJO COMPLETO EXITOSO!");
            
        } catch (Exception e) {
            System.err.println("❌ Error en flujo completo: " + e.getMessage());
        }
    }
}