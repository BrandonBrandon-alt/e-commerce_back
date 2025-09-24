package com.e_commerce.e_commerce_back.Account;

import java.time.LocalDate;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import static org.junit.jupiter.api.Assertions.*;

import com.e_commerce.e_commerce_back.dto.AuthResponseDTO;
import com.e_commerce.e_commerce_back.dto.LoginDTO;
import com.e_commerce.e_commerce_back.dto.RegisterUserDTO;
import com.e_commerce.e_commerce_back.services.implementation.AuthServiceImpl;

@SpringBootTest
@ActiveProfiles("test")
public class AuthTest {
    @Autowired
    AuthServiceImpl authServiceImpl;


    @Test
    void registerTest() {
        try {
            RegisterUserDTO registerUserDTO = new RegisterUserDTO("12345678", "John", "Doe", "john.doe@example.com", "3153033412", "M@mahermosa123", LocalDate.of(1990, 1, 1), true);
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

}