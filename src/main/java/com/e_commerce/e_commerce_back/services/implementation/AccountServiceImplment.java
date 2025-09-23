package com.e_commerce.e_commerce_back.services.implementation;

import com.e_commerce.e_commerce_back.services.interfaces.AccountService;
import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.e_commerce.e_commerce_back.dto.CreateUserDTO;
import com.e_commerce.e_commerce_back.exception.EmailIsExists;
import com.e_commerce.e_commerce_back.exception.IdNumberIsExists;
import com.e_commerce.e_commerce_back.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
@Transactional
@RequiredArgsConstructor
public class AccountServiceImplment implements AccountService {

    private final UserRepository userRepository;

    private boolean existsEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    private boolean existsIdNumber(String idNumber) {
        return userRepository.findByIdNumber(idNumber).isPresent();
    }

    public String createUser(CreateUserDTO cuenta) {
        CreateUserDTO user = new CreateUserDTO(cuenta.idNumber(), cuenta.name(), cuenta.lastName(), cuenta.email(),
                cuenta.phoneNumber(), cuenta.password(), cuenta.role());
        return "Cuenta creada exitosamente";
    }
    public String encryptPassword(String password) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(password);
    }

    @Override
    public String createAccount(CreateUserDTO cuenta) throws EmailIsExists, IdNumberIsExists {

        if (existsEmail(cuenta.email())) {
            throw new EmailIsExists("El email ya existe");
        }

        if (existsIdNumber(cuenta.idNumber())) {
            throw new IdNumberIsExists("El número de identificación ya existe");
        }

        return createUser(cuenta);
    }
}