package com.e_commerce.e_commerce_back.services.interfaces;

import com.e_commerce.e_commerce_back.dto.CreateAccountDTO;

public interface AccountService {

    /**
     * Metodo para crear una cuenta para el usuario.
     * @param cuenta
     * @return
     */
    String createAccount(CreateAccountDTO cuenta);

}