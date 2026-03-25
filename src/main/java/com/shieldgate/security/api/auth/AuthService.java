package com.shieldgate.security.api.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * JwtService handles:
 * - generating JWT tokens
 * - extracting data from tokens
 * - validating tokens
 *
 * This is a core part of authentication in the system.
 */
@Service
public class JwtService {

    // Secret key used to sign and verify JWT tokens
    // Loaded from application.properties
    private final SecretKey secretKey;

    // Token expiration time (e.g. 1 hour)
    private final long jwtExpiration;

    /**
     * Constructor
     * Converts the raw secret string into a cryptographic key
     */
    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration}") long jwtExpiration
    ) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.jwtExpiration = jwtExpiration;
    }

    /**
     * Extracts the username (email) from the token
     * The "subject" field in JWT = user identity
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic method to extract any claim from the token
     * Example claims: subject, expiration, issuedAt
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Parses the JWT and retrieves all claims (data inside token)
     * Also verifies the token signature using the secret key
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Generates a new JWT token for a user
     *
     * - subject = email (user identity)
     * - issuedAt = current time
     * - expiration = now + configured time
     */
    public String generateToken(String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    /**
     * Validates the token:
     * - checks username matches
     * - checks token is not expired
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Checks if token has expired
     */
    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }
}