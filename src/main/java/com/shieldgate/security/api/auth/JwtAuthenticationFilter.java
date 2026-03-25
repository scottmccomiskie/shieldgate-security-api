package com.shieldgate.security.api.auth;

import com.shieldgate.security.api.user.User;
import com.shieldgate.security.api.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter runs once for every incoming request.
 *
 * Its job is to:
 * - read the Authorization header
 * - extract the JWT token
 * - validate the token
 * - identify the user
 * - tell Spring Security the user is authenticated
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // Service used to extract and validate JWT tokens
    private final JwtService jwtService;

    // Repository used to load the user from the database
    private final UserRepository userRepository;

    public JwtAuthenticationFilter(JwtService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Read the Authorization header from the request
        // Example: Authorization: Bearer eyJhbGciOiJIUzI1Ni...
        String authHeader = request.getHeader("Authorization");

        // If there is no header, or it does not start with "Bearer ",
        // then there is no JWT token to process
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Remove "Bearer " so only the raw JWT token remains
        String jwt = authHeader.substring(7);

        // Extract the user email (stored as the token subject)
        String userEmail = jwtService.extractUsername(jwt);

        // Only continue if:
        // 1. an email was found in the token
        // 2. there is not already an authenticated user in the SecurityContext
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load the user from the database using the email from the token
            User user = userRepository.findByEmail(userEmail).orElse(null);

            // Validate token and confirm the user exists
            if (user != null && jwtService.isTokenValid(jwt, user)) {

                // Create an authentication object for Spring Security
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                user,
                                null,
                                user.getAuthorities()
                        );

                // Store the authenticated user in the SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Continue request through the rest of the filter chain
        filterChain.doFilter(request, response);
    }
}