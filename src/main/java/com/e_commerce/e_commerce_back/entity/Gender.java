package com.e_commerce.e_commerce_back.entity;

/**
 * Enum para representar el género tanto para usuarios como para productos
 */
public enum Gender {
    HOMBRE("Hombre"),
    MUJER("Mujer"),
    UNISEX("Unisex"),
    NINOS("Niños"),
    NINAS("Niñas"),
    OTRO("Otro"),
    PREFIERO_NO_DECIR("Prefiero no decir");
    
    private final String displayName;
    
    Gender(String displayName) {
        this.displayName = displayName;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    /**
     * Obtiene el género por su nombre de visualización
     */
    public static Gender fromDisplayName(String displayName) {
        for (Gender gender : Gender.values()) {
            if (gender.getDisplayName().equalsIgnoreCase(displayName)) {
                return gender;
            }
        }
        throw new IllegalArgumentException("No se encontró el género: " + displayName);
    }
    
    /**
     * Verifica si el género es aplicable para productos
     */
    public boolean isProductGender() {
        return this == HOMBRE || this == MUJER || this == UNISEX || 
               this == NINOS || this == NINAS;
    }
    
    /**
     * Verifica si el género es aplicable para usuarios
     */
    public boolean isUserGender() {
        return this == HOMBRE || this == MUJER || this == OTRO || 
               this == PREFIERO_NO_DECIR;
    }
}
