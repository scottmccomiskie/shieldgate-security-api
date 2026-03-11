package com.shieldgate.security.api.auth;
import com.shieldgate.security.api.auth.dto.LoginRequest;
import com.shieldgate.security.api.auth.dto.LoginResponse;
import com.shieldgate.security.api.auth.dto.RegisterRequest;
import com.shieldgate.security.api.auth.dto.RegisterResponse;
import com.shieldgate.security.api.user.User;
import com.shieldgate.security.api.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;


/**
 * Controller = the "front door" to your API.
 * It listens for web requests and returns responses.
 */

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }
    /**
     * Endpoint: POST /api/v1/auth/register
     * - @RequestBody means: take the JSON from the request and put it into RegisterRequest
     * - @Valid means: run the validation rules in RegisterRequest (email format, password length, etc)
     */

    @PostMapping("/login")
        public LoginResponse login (@Valid @RequestBody LoginRequest request) {
            User user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Password"));

            boolean passwordMatches = passwordEncoder.matches(
                    request.getPassword(),
                    user.getPassword()

            );

            if (!passwordMatches) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
            }

            String token = jwtService.generateToken(user.getEmail());

            return new LoginResponse(token);


        }




    @PostMapping("/register")
    // Tells Spring:
    // 1. Read JSON body
    // 2. Convert to RegisterRequest
    // 3. Validate using annotations
    public RegisterResponse register (@Valid @RequestBody RegisterRequest request){
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        User user = new User (
                request.getEmail(),
                hashedPassword
        );

        userRepository.save(user);

        // For bow we just simulate sucess
        return new RegisterResponse(
            "user registered successful with email" + request.getEmail()
        );


    }

}

