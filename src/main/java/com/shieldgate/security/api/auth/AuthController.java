package com.shieldgate.security.api.auth;

import com.shieldgate.security.api.auth.dto.LoginRequest;
import com.shieldgate.security.api.auth.dto.LoginResponse;
import com.shieldgate.security.api.auth.dto.RegisterRequest;
import com.shieldgate.security.api.auth.dto.RegisterResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private  final AuthService authService;


    public AuthController(AuthService authService){
        this.authService = authService;
    }


    @PostMapping("/login")
        public LoginResponse login (@Valid @RequestBody LoginRequest request) {
            return authService.login(request);
        }


    @PostMapping("/register")
    public RegisterResponse register (@Valid @RequestBody RegisterRequest request) {
        return authService.register(request);
    }

}

