package com.securefromscratch.busybee.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * Represents a registered user account.
 * Roles: ADMIN (full access), CREATOR (can create tasks), TRIAL (limited: one open task at a time)
 */
public class UserAccount implements UserDetails {
    public enum Role { ADMIN, CREATOR, TRIAL }

    private final String username;
    private final String passwordHash;   // BCrypt hash – raw password is never stored
    private final Role role;

    public UserAccount(String username, String passwordHash, Role role) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
    }

    public Role getRole() { return role; }

    @Override public String getUsername() { return username; }
    @Override public String getPassword() { return passwordHash; }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    @Override public boolean isAccountNonExpired()  { return true; }
    @Override public boolean isAccountNonLocked()   { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled()            { return true; }
}
