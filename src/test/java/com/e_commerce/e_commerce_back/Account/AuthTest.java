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
import com.e_commerce.e_commerce_back.dto.RefreshTokenDTO;
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


    

}
