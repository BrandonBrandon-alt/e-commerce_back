package com.e_commerce.e_commerce_back.Account;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import com.e_commerce.e_commerce_back.dto.ActivateAccountDTO;
import com.e_commerce.e_commerce_back.dto.LoginDTO;
import com.e_commerce.e_commerce_back.dto.RegisterUserDTO;
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
    void registerTest() {
        try {
            RegisterUserDTO registerUserDTO = new RegisterUserDTO("12345678", "John", "Doe", "brandonmontealegre15@gmail.com", "3153033412", "M@mahermosa123", LocalDate.of(1990, 1, 1), true);
            System.out.println("Starting register test...");
            authServiceImpl.register(registerUserDTO);
            System.out.println("Register test completed successfully!");
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    @Test
    void loginTest() {
        try {
            LoginDTO loginDTO = new LoginDTO("john.doe@example.com", "M@mahermosa123");
            System.out.println("Starting login test...");
            authServiceImpl.login(loginDTO);
            System.out.println("Login test completed successfully!");
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
     }

     @Test
     void activateAccountTest() {
        try {
            ActivateAccountDTO activateAccountDTO = new ActivateAccountDTO("john.doe@example.com", "123456");
            System.out.println("Starting activate account test...");
            authServiceImpl.activateAccount(activateAccountDTO);
            System.out.println("Activate account test completed successfully!");
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
     void resetPasswordTest() {
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

}