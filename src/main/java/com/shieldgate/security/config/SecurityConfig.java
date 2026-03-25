package com.shieldgate.security.config;

import com.shieldgate.security.api.auth.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig defines the security rules for the application.
 *
 * It controls:
 * - which endpoints are public
 * - which endpoints require authentication
 * - where the JWT filter is added
 * - which password encoder is used
 */
@Configuration
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // Disable CSRF because this project is a stateless REST API
                .csrf(csrf -> csrf.disable())

                // Define which requests are allowed without authentication
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/v1/auth/register").permitAll()
                        .requestMatchers("/api/v1/auth/login").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )

                // Allow the H2 console to load in the browser frame
                .headers(headers -> headers
                        .frameOptions(frame -> frame.disable())
                )

                // Add our custom JWT filter before Spring's authentication filter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt is used to securely hash passwords
        return new BCryptPasswordEncoder();
    }
}