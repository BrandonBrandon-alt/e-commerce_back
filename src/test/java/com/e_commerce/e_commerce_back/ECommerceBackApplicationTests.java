package com.e_commerce.e_commerce_back;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@ActiveProfiles("test")
class ECommerceBackApplicationTests {

    @Test
    void contextLoads() {
    }
}

@SpringBootTest
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
class ECommerceBackH2ApplicationTests {

    @Test
    void contextLoads() {
        System.out.println("✅ Contexto cargado correctamente con H2");
    }
}

@SpringBootTest(properties = {
    "spring.profiles.active=test",
    "spring.datasource.url=jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.datasource.driver-class-name=org.h2.Driver"
})
class ECommerceBackExplicitH2Tests {

    @Test
    void contextLoads() {
        System.out.println("✅ Contexto cargado con configuración explícita");
    }
}