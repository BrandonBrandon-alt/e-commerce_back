#!/bin/bash

# Script para probar el bloqueo de cuenta por intentos fallidos
# Ejecuta 6 intentos de login con contraseña incorrecta

BASE_URL="http://localhost:8080"
EMAIL="test@example.com"
WRONG_PASSWORD="wrongpassword123"

echo "🔐 Probando bloqueo de cuenta por intentos fallidos"
echo "=================================================="
echo "Email: $EMAIL"
echo "Contraseña incorrecta: $WRONG_PASSWORD"
echo "Máximo de intentos permitidos: 5"
echo ""

for i in {1..6}
do
  echo "📍 Intento #$i"
  echo "-------------------"
  
  RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{
      \"email\": \"$EMAIL\",
      \"password\": \"$WRONG_PASSWORD\"
    }")
  
  # Extraer el código HTTP
  HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
  BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS/d')
  
  # Mostrar respuesta formateada
  echo "Status: $HTTP_STATUS"
  echo "Respuesta:"
  echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
  echo ""
  
  # Si el intento 5 o 6 retorna 423 (LOCKED), la cuenta está bloqueada
  if [ "$HTTP_STATUS" == "423" ]; then
    echo "✅ Cuenta bloqueada correctamente después de múltiples intentos fallidos"
    break
  fi
  
  # Pequeña pausa entre intentos
  sleep 1
done

echo ""
echo "=================================================="
echo "✅ Prueba completada"
echo ""
echo "📝 Notas:"
echo "- Los primeros 4 intentos deben retornar 401 con mensaje de intentos restantes"
echo "- El 5to intento debe bloquear la cuenta y retornar 423 (LOCKED)"
echo "- El 6to intento debe retornar 423 indicando que la cuenta está bloqueada"
echo ""
echo "🔓 Para desbloquear la cuenta, usa el endpoint:"
echo "POST $BASE_URL/api/auth/request-unlock"
