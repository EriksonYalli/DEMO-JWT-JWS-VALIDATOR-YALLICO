package com.demo.val.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class ValidationService {

    private final ObjectMapper mapper = new ObjectMapper();
    private static final String DEFAULT_SECRET = "demo-secret-hs256-2024-muy-segura!";

    public Map<String, Object> validate(String token, String publicKeyStr, String secret) {
        Map<String, Object> result = new HashMap<>();
        try {
            String alg = extractAlgorithm(token);
            Jws<Claims> jws;

            if ("HS256".equals(alg)) {
                String usedSecret = (secret != null && !secret.isBlank()) ? secret : DEFAULT_SECRET;
                SecretKey key = Keys.hmacShaKeyFor(usedSecret.getBytes(StandardCharsets.UTF_8));
                jws = Jwts.parser()
                        .verifyWith(key).build()
                        .parseSignedClaims(token);
            } else if ("RS256".equals(alg)) {
                if (publicKeyStr == null || publicKeyStr.isBlank()) {
                    result.put("valid", false);
                    result.put("error", "Se requiere la Clave Pública para RS256");
                    return result;
                }
                PublicKey publicKey = decodePublicKey(publicKeyStr);
                jws = Jwts.parser()
                        .verifyWith(publicKey).build()
                        .parseSignedClaims(token);
            } else {
                result.put("valid", false);
                result.put("error", "Algoritmo no soportado o desconocido: " + alg);
                return result;
            }

            result.put("valid", true);
            result.put("header", extractHeader(token));
            result.put("payload", jws.getPayload());
            result.put("algorithm", alg);

        } catch (JwtException e) {
            result.put("valid", false);
            result.put("error", "Error de validación: " + e.getMessage());
        } catch (Exception e) {
            result.put("valid", false);
            result.put("error", "Error interno: " + e.getMessage());
        }
        return result;
    }

    private String extractAlgorithm(String token) {
        try {
            Map<?, ?> header = extractHeader(token);
            return (String) header.get("alg");
        } catch (Exception e) {
            return "UNKNOWN";
        }
    }

    private Map<?, ?> extractHeader(String token) throws Exception {
        String headerEncoded = token.split("\\.")[0];
        byte[] decoded = Base64.getUrlDecoder().decode(headerEncoded);
        return mapper.readValue(decoded, Map.class);
    }

    private PublicKey decodePublicKey(String base64Key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
