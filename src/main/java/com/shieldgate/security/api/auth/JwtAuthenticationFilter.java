package com.shieldgate.security.api.auth;


import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.Collections;

@Component
public class JwtAuthenticationFilter  extends OncePerRequestFilter {

    // dependency 1: JwtAuthentication needs to:
    //read the Authorization header * check if it starts
    // with Bearer * extract the token * read the email from the token
    private final JwtService jwtService;

    // dependency 2: load the user from the database maybe
    private final UserDetailsService userDetailsService;

    // this is the constructor using the above dependencies
    public JwtAuthenticationFilter (
            JwtService jwtService,
            UserDetailsService userDetailsService
    ) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal (
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        //STEP 1:
        //Get the Authorization header from the incoming request
        // Example:
        // Authorization: Bearer

        String authHeader = request.getHeader("Authorization");

        //STEP 2:
        // if there is no Authorization header
        // or it doesnt start with Bearer
        // then there no JWT token for us to check

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            //pass request to the next filter
            filterChain.doFilter(request, response);
            return;
        }

        //STEP 3:
        // Remove "Bearer " from the start of the header
        // so only token remains
        String jwt = authHeader.substring(7);

        //Step 4:
        // Use JwtService to extract email/username from the token
        String userEmail = jwtService.extractUsername(jwt);

        //STEP 5:
        // only continue if found an email and there not
        // already an authenticated user in the security context

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            //STEP 6
            // Load the user from the database using the email from the token
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            //STEP 7
            // Check of the token is valid for this user
            if (jwtService.isTokenValid(jwt, userDetails)) {

                //STEP 8:
                // Create an authentication object for spring security
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );

                //STEP 9
                // Tell Spring Security this user is now authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }

        }

        //STEP 10:
        // Continue the request through the rest of the filter chain
        filterChain.doFilter(request, response);
    }


}
