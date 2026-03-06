package com.shieldgate.security.api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
/*
 This class represents the JSON body sent during registration.

 When someone sends:
 {
   "email": "scott@test.com",
   "password": "Password123"
 }

 Spring converts that JSON into this object automatically.
*/
public record RegisterRequest (

            // Must be a valid email format
            @Email(message = "Email must be valid")

            // Cannot be empty
            @NotBlank(message = "Email is required")
            String email,

            @NotBlank(message = "Password is required")

            // Must be at least 8 characters
            @Size(min = 8, message = "Password must be at least 8 characters")
            String password
    ){}

