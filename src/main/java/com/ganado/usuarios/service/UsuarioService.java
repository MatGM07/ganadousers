package com.ganado.usuarios.service;

import com.ganado.usuarios.dto.*;
import com.ganado.usuarios.model.Usuario;
import com.ganado.usuarios.repository.UsuarioRepository;
import io.jsonwebtoken.security.Password;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UsuarioService {

    private final UsuarioRepository repo;
    private final JavaMailSender mailSender;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public Usuario register(RegisterDTO dto) {
        Usuario user = Usuario.builder()
                .nombre(dto.getName())
                .email(dto.getEmail())
                .password(encoder.encode(dto.getPassword()))
                .build();
        user.setFechaCreacion(LocalDateTime.now());
        return repo.save(user);
    }

    public Usuario login(LoginDTO dto) {
        Usuario user = repo.findByEmail(dto.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!encoder.matches(dto.getPassword(), user.getPassword())) {
            throw new RuntimeException("Contraseña incorrecta");
        }

        return user; // en microservicios usas JWT fuera
    }

    public List<Usuario> findAll() {
        return repo.findAll();
    }

    public void requestPasswordReset(ResetPasswordDTO dto) {
        Usuario user = repo.findByEmail(dto.getEmail())
                .orElseThrow(() -> new RuntimeException("No existe ese correo"));

        String code = UUID.randomUUID().toString().substring(0, 6);
        user.setResetCode(code);
        repo.save(user);

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(user.getEmail());
        msg.setSubject("Código para cambio de contraseña");
        msg.setText("Tu código es: " + code);
        mailSender.send(msg);
    }

    public void confirmPasswordReset(ConfirmCodeDTO dto) {
        Usuario user = repo.findByResetCode(dto.getCode())
                .orElseThrow(() -> new RuntimeException("Código inválido"));

    }

    public void newPassword(PasswordDTO dto){
        Usuario user = repo.findByEmail(dto.getEmail())
                .orElseThrow(() -> new RuntimeException("Error al actualizar"));

        user.setPassword(encoder.encode(dto.getPassword()));
        user.setResetCode(null);
        repo.save(user);

    }

    public boolean emailExists(String email) {
        return repo.existsByEmail(email);
    }
}
