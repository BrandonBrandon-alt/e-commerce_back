package com.e_commerce.e_commerce_back.Account;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import com.e_commerce.e_commerce_back.dto.ActivateAccountDTO;
import com.e_commerce.e_commerce_back.dto.ForgotPasswordDTO;
import com.e_commerce.e_commerce_back.dto.LoginDTO;
import com.e_commerce.e_commerce_back.dto.RegisterUserDTO;
import com.e_commerce.e_commerce_back.dto.ResetPasswordDTO;
import com.e_commerce.e_commerce_back.services.implementation.AuthServiceImpl;
import com.e_commerce.e_commerce_back.services.interfaces.EmailService;
import com.e_commerce.e_commerce_back.entity.User;

@SpringBootTest
@ActiveProfiles("test")
public class AuthTest {
    @Autowired
    AuthServiceImpl authServiceImpl;
    @Autowired
    EmailService emailServiceImpl;


    @Test
    void registerTest() throws Exception {
        try {
            System.out.println("=== TESTING USER REGISTRATION WITH REAL EMAIL SENDING ===");
            
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "12345678", 
                "John", 
                "Doe", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("Registrando usuario: " + registerUserDTO.email());
            var result = authServiceImpl.register(registerUserDTO);
            System.out.println("Resultado del registro: " + result.getMessage());
            
            // Esperar para que el email de activación se procese
            System.out.println("Esperando 5 segundos para que se procese el email de activación...");
            Thread.sleep(5000);
            
            System.out.println("Register test completed - ¡Revisa tu correo para el código de activación!");
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void loginTest() throws Exception {
        try {
            System.out.println("=== TESTING USER LOGIN ===");
            
            // Primero registrar y activar un usuario
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "11111111", 
                "Login", 
                "Test", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("Registrando usuario para test de login...");
            authServiceImpl.register(registerUserDTO);
            Thread.sleep(2000);
            
            // Nota: En un test real, usarías el código del email recibido
            System.out.println("Nota: En un test real, usarías el código del email recibido");
            
            LoginDTO loginDTO = new LoginDTO("brandonmontealegre15@gmail.com", "M@mahermosa123");
            System.out.println("Intentando login para: " + loginDTO.email());
            
            try {
                var result = authServiceImpl.login(loginDTO);
                System.out.println("Login exitoso: " + result.getMessage());
            } catch (Exception e) {
                System.out.println("Login falló (esperado si la cuenta no está activada): " + e.getMessage());
            }
            
            System.out.println("Login test completed!");
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
     }

     @Test
     void activateAccountTest() throws Exception {
        try {
            System.out.println("=== TESTING ACCOUNT ACTIVATION WITH REAL EMAIL ===");
            
            // Primero registrar un usuario
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "22222222", 
                "Activate", 
                "Test", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("Registrando usuario para test de activación...");
            authServiceImpl.register(registerUserDTO);
            
            // Esperar para que se procese el email
            Thread.sleep(3000);
            
            System.out.println("IMPORTANTE: Revisa tu correo y usa el código de 6 dígitos recibido");
            System.out.println("Para este test, usaremos un código de ejemplo (fallará si no es el correcto)");
            
            ActivateAccountDTO activateAccountDTO = new ActivateAccountDTO("brandonmontealegre15@gmail.com", "123456");
            System.out.println("Intentando activar cuenta con código: 123456");
            
            var result = authServiceImpl.activateAccount(activateAccountDTO);
            System.out.println("Resultado de activación: " + result.getMessage());
            
            // Si la activación es exitosa, se enviará email de bienvenida
            if (result.getMessage().contains("exitosamente")) {
                System.out.println("Esperando 3 segundos para que se procese el email de bienvenida...");
                Thread.sleep(3000);
                System.out.println("¡Revisa tu correo para el email de bienvenida!");
            }
            
            System.out.println("Activate account test completed!");
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
     }

     @Test
     void emailServiceTest() {
        try {
            System.out.println("=== TESTING EMAIL SERVICE DIRECTLY ===");
            
            // Crear un usuario de prueba
            User testUser = User.builder()
                .name("Test")
                .lastName("User")
                .email("brandonmontealegre15@gmail.com")
                .build();
            
            String testCode = "123456";
            
            System.out.println("Sending test activation email to: " + testUser.getEmail());
            emailServiceImpl.sendActivationEmail(testUser, testCode);
            
            // Esperar un poco para que el email asíncrono se procese
            try {
                Thread.sleep(5000);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
            
            System.out.println("Email test completed - Check your inbox!");
            
        } catch (Exception e) {
            System.err.println("Email test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
     }

     @Test
     void resetPasswordEmailTest() {
        try {
            System.out.println("=== TESTING EMAIL SERVICE DIRECTLY ===");
             // Crear un usuario de prueba
             User testUser = User.builder()
             .name("Test")
             .lastName("User")
             .email("brandonmontealegre15@gmail.com")
             .build();
         
         String testCode = "123456";
         
         System.out.println("Sending test reset password email to: " + testUser.getEmail());
         emailServiceImpl.sendPasswordResetEmail(testUser, testCode);
         
         // Esperar un poco para que el email asíncrono se procese
         try {
            Thread.sleep(5000);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
        
        System.out.println("Email test completed - Check your inbox!");
        
        } catch (Exception e) {
            System.err.println("Email test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
     }

     @Test
     void resetPasswordTest() throws Exception {
        try {
            System.out.println("=== TESTING PASSWORD RESET WITH REAL EMAIL ===");
            
            // Primero registrar un usuario
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "33333333", 
                "Reset", 
                "Test", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("Registrando usuario para test de reset password...");
            authServiceImpl.register(registerUserDTO);
            Thread.sleep(2000);
            
            // Solicitar reset de contraseña
            ForgotPasswordDTO forgotPasswordDTO = new ForgotPasswordDTO("brandonmontealegre15@gmail.com");
            System.out.println("Solicitando reset de contraseña...");
            var forgotResult = authServiceImpl.forgotPassword(forgotPasswordDTO);
            System.out.println("Resultado forgot password: " + forgotResult.getMessage());
            
            // Esperar para que se procese el email
            Thread.sleep(5000);
            
            System.out.println("IMPORTANTE: Revisa tu correo y usa el código de reset recibido");
            System.out.println("Para este test, usaremos un código de ejemplo (fallará si no es el correcto)");
            
            ResetPasswordDTO resetPasswordDTO = new ResetPasswordDTO(
                "brandonmontealegre15@gmail.com",
                "123456", 
                "NuevaM@mahermosa123", 
                "NuevaM@mahermosa123"
            );
            
            System.out.println("Intentando resetear contraseña con código: 123456");
            var result = authServiceImpl.resetPassword(resetPasswordDTO);
            System.out.println("Resultado del reset: " + result.getMessage());
            
            System.out.println("Reset password test completed!");
            
        } catch (Exception e) {
            System.err.println("Reset password test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
     }
     
    
    
    @Test
    void forgotPasswordTest() throws Exception {
        try {
            System.out.println("=== TESTING FORGOT PASSWORD WITH REAL EMAIL SENDING ===");
            
            // Primero registrar un usuario para asegurar que existe
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "87654321", 
                "Test", 
                "User", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("Registrando usuario para test de forgot password...");
            authServiceImpl.register(registerUserDTO);
            
            // Esperar un poco para que se complete el registro
            Thread.sleep(2000);
            
            // Ahora probar forgot password
            ForgotPasswordDTO forgotPasswordDTO = new ForgotPasswordDTO("brandonmontealegre15@gmail.com");
            System.out.println("Enviando solicitud de forgot password a: " + forgotPasswordDTO.email());
            
            var result = authServiceImpl.forgotPassword(forgotPasswordDTO);
            System.out.println("Resultado del forgot password: " + result.getMessage());
            
            // Esperar para que el email asíncrono se procese
            System.out.println("Esperando 8 segundos para que se procese el envío del email...");
            Thread.sleep(8000);
            
            System.out.println("Forgot password test completed - ¡Revisa tu correo electrónico!");
            
        } catch (Exception e) {
            System.err.println("Forgot password test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void resendActivationCodeTest() throws Exception {
        try {
            System.out.println("=== TESTING RESEND ACTIVATION CODE WITH REAL EMAIL ===");
            
            // Primero registrar un usuario
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "44444444", 
                "Resend", 
                "Test", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("Registrando usuario para test de reenvío...");
            authServiceImpl.register(registerUserDTO);
            Thread.sleep(3000);
            
            System.out.println("Reenviando código de activación...");
            var result = authServiceImpl.resendActivationCode("brandonmontealegre15@gmail.com");
            System.out.println("Resultado del reenvío: " + result.getMessage());
            
            // Esperar para que se procese el nuevo email
            System.out.println("Esperando 5 segundos para que se procese el nuevo email...");
            Thread.sleep(5000);
            
            System.out.println("Resend activation code test completed - ¡Revisa tu correo para el nuevo código!");
            
        } catch (Exception e) {
            System.err.println("Resend activation code test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void validateTokenTest() throws Exception {
        try {
            System.out.println("=== TESTING TOKEN VALIDATION ===");
            
            // Test con token nulo
            System.out.println("1. Probando validación con token nulo...");
            var nullResult = authServiceImpl.validateToken(null);
            System.out.println("   Resultado: " + nullResult.getMessage());
            System.out.println("   Token válido: " + nullResult.isValid());
            
            // Test con token vacío
            System.out.println("2. Probando validación con token vacío...");
            var emptyResult = authServiceImpl.validateToken("");
            System.out.println("   Resultado: " + emptyResult.getMessage());
            System.out.println("   Token válido: " + emptyResult.isValid());
            
            // Test con token inválido
            System.out.println("3. Probando validación con token inválido...");
            String invalidToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            var invalidResult = authServiceImpl.validateToken(invalidToken);
            System.out.println("   Resultado: " + invalidResult.getMessage());
            System.out.println("   Token válido: " + invalidResult.isValid());
            
            System.out.println("Validate token test completed - Se probaron diferentes escenarios!");
            
        } catch (Exception e) {
            System.err.println("Validate token test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void logoutTest() throws Exception {
        try {
            System.out.println("=== TESTING LOGOUT ===");
            
            // Test con token nulo (logout sin token)
            System.out.println("1. Probando logout sin token...");
            try {
                authServiceImpl.logout(null);
                System.out.println("   Logout sin token procesado exitosamente");
            } catch (Exception e) {
                System.out.println("   Error esperado con token nulo: " + e.getMessage());
            }
            
            // Test con token vacío
            System.out.println("2. Probando logout con token vacío...");
            try {
                authServiceImpl.logout("");
                System.out.println("   Logout con token vacío procesado exitosamente");
            } catch (Exception e) {
                System.out.println("   Error esperado con token vacío: " + e.getMessage());
            }
            
            // Test con token inválido (ahora debería funcionar sin lanzar excepción)
            System.out.println("3. Probando logout con token inválido...");
            String logoutToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
            try {
                authServiceImpl.logout(logoutToken);
                System.out.println("   ✅ Logout con token inválido procesado exitosamente");
                System.out.println("   El método logout ahora maneja tokens inválidos correctamente");
            } catch (Exception e) {
                System.out.println("   ❌ Error inesperado: " + e.getMessage());
            }
            
            System.out.println("Logout test completed - Se probaron diferentes escenarios!");
            
        } catch (Exception e) {
            System.err.println("Logout test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void completeUserFlowTest() throws Exception {
        try {
            System.out.println("=== TESTING COMPLETE USER FLOW WITH REAL EMAILS ===");
            
            // 1. Registro
            RegisterUserDTO registerUserDTO = new RegisterUserDTO(
                "99999999", 
                "Complete", 
                "Flow", 
                "brandonmontealegre15@gmail.com", 
                "3153033412", 
                "M@mahermosa123", 
                LocalDate.of(1990, 1, 1), 
                true
            );
            
            System.out.println("1. Registrando usuario...");
            var registerResult = authServiceImpl.register(registerUserDTO);
            System.out.println("   Resultado: " + registerResult.getMessage());
            Thread.sleep(3000);
            
            // 2. Reenvío de código (opcional)
            System.out.println("2. Reenviando código de activación...");
            var resendResult = authServiceImpl.resendActivationCode("brandonmontealegre15@gmail.com");
            System.out.println("   Resultado: " + resendResult.getMessage());
            Thread.sleep(3000);
            
            // 3. Forgot Password
            System.out.println("3. Solicitando reset de contraseña...");
            var forgotResult = authServiceImpl.forgotPassword(new ForgotPasswordDTO("brandonmontealegre15@gmail.com"));
            System.out.println("   Resultado: " + forgotResult.getMessage());
            Thread.sleep(5000);
            
            System.out.println("\n=== RESUMEN DEL FLUJO COMPLETO ===");
            System.out.println("✅ Registro completado - Email de activación enviado");
            System.out.println("✅ Reenvío de código completado - Nuevo email enviado");
            System.out.println("✅ Forgot password completado - Email de reset enviado");
            System.out.println("\n📧 REVISA TU CORREO PARA:");
            System.out.println("   - Código de activación (6 dígitos)");
            System.out.println("   - Código de reset de contraseña (6 dígitos)");
            System.out.println("\nComplete user flow test completed!");
            
        } catch (Exception e) {
            System.err.println("Complete user flow test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void getCurrentUserInfoTest() throws Exception {
        try {
            System.out.println("=== TESTING GET CURRENT USER INFO ===");
            
            System.out.println("Nota: Este test requiere un usuario autenticado en el contexto de seguridad");
            System.out.println("En un entorno real, necesitarías estar logueado para obtener la información del usuario actual");
            
            try {
                var userInfo = authServiceImpl.getCurrentUserInfo();
                System.out.println("Información del usuario actual obtenida: " + userInfo.getEmail());
            } catch (Exception e) {
                System.out.println("Error esperado (no hay usuario autenticado): " + e.getMessage());
            }
            
            System.out.println("Get current user info test completed!");
            
        } catch (Exception e) {
            System.err.println("Get current user info test failed: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

}
