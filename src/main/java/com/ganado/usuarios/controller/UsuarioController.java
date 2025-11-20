package com.ganado.usuarios.controller;

import com.ganado.usuarios.dto.*;
import com.ganado.usuarios.model.Usuario;
import com.ganado.usuarios.security.JwtService;
import com.ganado.usuarios.service.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UsuarioController {

    private final UsuarioService service;
    private final JwtService jwtService;


    @PostMapping("/register")
    public Usuario register(@RequestBody RegisterDTO dto) {
        return service.register(dto);
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginDTO dto) {
        Usuario user = service.login(dto);

        String token = jwtService.createToken(user);  // 👈 genera JWT

        return Map.of(
                "token", token,
                "user", user
        );
    }

    @GetMapping
    public List<Usuario> getAll() {
        return service.findAll();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordDTO dto) {
        service.requestPasswordReset(dto);
        return ResponseEntity.ok(Map.of("message", "Código enviado"));
    }

    @PostMapping("/reset-password/confirm")
    public ResponseEntity<?> confirmReset(@RequestBody ConfirmCodeDTO dto) {
        service.confirmPasswordReset(dto);
        return ResponseEntity.ok(Map.of("message", "Código confirmado"));
    }

    @PostMapping("/reset-password/new")
    public ResponseEntity<?> confirmPassword(@RequestBody PasswordDTO dto){
        service.newPassword(dto);
        return ResponseEntity.ok(Map.of("message", "Contraseña actualizada"));
    }

    @GetMapping("/checkemail")
    public Map<String, Boolean> checkEmail(@RequestParam String email) {
        System.out.println("email: "+email);
        boolean exists = service.emailExists(email);
        System.out.println(exists);
        return Map.of("exists", exists);
    }
}