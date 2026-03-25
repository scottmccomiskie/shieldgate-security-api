package com.shieldgate.security.api.user;

import jakarta.persistence.*;

// Spring Security imports
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/*
 * This class represents a user in the database.
 *
 * It is both:
 * 1) A JPA Entity (stored in the database)
 * 2) A Spring Security User (implements UserDetails)
 *
 * Because it implements UserDetails, Spring Security can use this class
 * directly when authenticating users.
 */

@Entity
@Table(name = "users")
public class User implements UserDetails {

    /*
     * Primary key for the database table.
     * Generated automatically by the database.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /*
     * The user's email.
     * In this system we use the email as the username.
     */
    private String email;

    /*
     * The hashed password (BCrypt).
     * We NEVER store raw passwords.
     */
    private String password;

    /*
     * Number of failed login attempts.
     * Used to detect brute force attacks.
     */
    private int failedLoginAttempts;

    /*
     * Whether the account has been locked due to too many failed logins.
     */
    private boolean accountLocked;

    /*
     * Default constructor required by JPA.
     */
    public User() {
    }

    /*
     * Constructor used when creating a new user.
     */
    public User(String email, String password) {
        this.email = email;
        this.password = password;
    }

    /*
     * Getter for the database ID.
     */
    public Long getId() {
        return id;
    }

    /*
     * Return the user's email.
     */
    public String getEmail() {
        return email;
    }

    /*
     * Set the user's email.
     */
    public void setEmail(String email) {
        this.email = email;
    }

    /*
     * Return the user's password.
     * This is required by Spring Security.
     */
    @Override
    public String getPassword() {
        return password;
    }

    /*
     * Set the user's password (normally hashed with BCrypt).
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /*
     * Get number of failed login attempts.
     */
    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    /*
     * Set number of failed login attempts.
     */
    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    /*
     * Check if the account is locked.
     */
    public boolean isAccountLocked() {
        return accountLocked;
    }

    /*
     * Lock or unlock the account.
     */
    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    /*
     * Returns the roles/permissions of the user.
     *
     * For now every user gets ROLE_USER.
     * Later we can add ROLE_ADMIN.
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    /*
     * Spring Security asks: "What is the username?"
     *
     * In our system we use email as the username.
     */
    @Override
    public String getUsername() {
        return email;
    }

    /*
     * Whether the account has expired.
     * We are not using expiration right now.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /*
     * Whether the account is locked.
     *
     * Spring Security expects the opposite:
     * true = NOT locked
     * false = locked
     *
     * So we invert the value.
     */
    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    /*
     * Whether the user's credentials (password) have expired.
     * Not used in this project yet.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /*
     * Whether the user account is enabled.
     * Could be used for banning users or email verification later.
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}