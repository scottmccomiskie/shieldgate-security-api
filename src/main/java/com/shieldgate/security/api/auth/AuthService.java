package com.shieldgate.security.api.auth;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import com.shieldgate.security.api.user.User;
import com.shieldgate.security.api.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.shieldgate.security.api.auth.dto.LoginRequest;
import com.shieldgate.security.api.auth.dto.LoginResponse;
import com.shieldgate.security.api.auth.dto.RegisterRequest;
import com.shieldgate.security.api.auth.dto.RegisterResponse;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    // find user by email or return 401 if not found
    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Credentials"));


        // Prevent login if account is locked
        if (user.isAccountLocked()) {
            throw new ResponseStatusException(HttpStatus.LOCKED, "Account is locked");
        }

        // Compare raw password with hashed password in database
        boolean passwordMatches = passwordEncoder.matches(
                request.getPassword(),
                user.getPassword()
        );

        // Handle failed login attempts
        if (!passwordMatches) {
            user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

            // Lock account after 5 failed attempts
            if (user.getFailedLoginAttempts()>= 5){
                user.setAccountLocked(true);
            }

            userRepository.save(user);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Credentials");
        }

        // Reset failed attempts on successful login
        user.setFailedLoginAttempts(0);
        user.setAccountLocked(false);
        userRepository.save(user);

        // Generate JWT token for authenticated user
        String token = jwtService.generateToken(user.getEmail());

        return new LoginResponse(token);

    }

    public RegisterResponse register(RegisterRequest request) {
        // Prevent duplicate email registration
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {

            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email is already registered");
        }

        // hash password before storing
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // Create new user entity
        User user = new User(
                request.getEmail(),
                hashedPassword
        );

        // save user to database
        userRepository.save(user);

        // returns success message
        return new RegisterResponse(
                "user registered successfully with email" + request.getEmail());

    }



}
