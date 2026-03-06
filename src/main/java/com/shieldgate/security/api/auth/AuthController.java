package com.shieldgate.security.api.auth;

import com.shieldgate.security.api.auth.dto.RegisterRequest;
import com.shieldgate.security.api.auth.dto.RegisterResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

/**
 * Controller = the "front door" to your API.
 * It listens for web requests and returns responses.
 */

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    /**
     * Endpoint: POST /api/v1/auth/register
     *
     * - @RequestBody means: take the JSON from the request and put it into RegisterRequest
     * - @Valid means: run the validation rules in RegisterRequest (email format, password length, etc)
     */
    @PostMapping("/register")
    // Tells Spring:
    // 1. Read JSON body
    // 2. Convert to RegisterRequest
    // 3. Validate using annotations
    public RegisterResponse register (@Valid @RequestBody RegisterRequest request){

        // For bow we just simulate sucess
        return new RegisterResponse(
            "user registered sucesscully with email" + request.email()
        );


    }

}
