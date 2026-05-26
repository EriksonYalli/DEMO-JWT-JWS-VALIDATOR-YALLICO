package com.demo.val.controller;

import com.demo.val.service.ValidationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/api/validate")
public class ValidationController {

    private final ValidationService validationService;

    public ValidationController(ValidationService validationService) {
        this.validationService = validationService;
    }

    @PostMapping
    public Mono<ResponseEntity<Map<String, Object>>> validate(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        String publicKey = request.get("publicKey");
        String secret = request.get("secret");

        if (token == null || token.isBlank()) {
            return Mono.just(ResponseEntity.badRequest().body(Map.of(
                    "valid", false, "error", "Se requiere un token")));
        }

        Map<String, Object> result = validationService.validate(token, publicKey, secret);
        return Mono.just(ResponseEntity.ok(result));
    }
}
