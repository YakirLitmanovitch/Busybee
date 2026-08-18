package com.securefromscratch.busybee.auth;

import com.securefromscratch.busybee.safety.Password;
import com.securefromscratch.busybee.safety.Username;

/**
 * Registration request DTO.
 * Both fields use OWASP SafeTypes value types:
 *  - Username: extends BoundedWord (3–20 chars, alphanumeric/underscore)
 *  - Password: custom type (8–64 chars, requires upper, lower, digit, special)
 */
public record RegisterRequest(Username username, Password password) {}
