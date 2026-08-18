package com.securefromscratch.busybee.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
public class RegistrationController {
    private static final Logger LOGGER = LoggerFactory.getLogger(RegistrationController.class);

    @Autowired private UsersStorage m_users;
    @Autowired private PasswordEncoder m_encoder;

    /**
     * POST /register
     * Registers a new TRIAL user.
     * Username and password are validated via SafeTypes value types in RegisterRequest.
     */
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest req) {
        try {
            String username = req.username().getValue();
            if (m_users.exists(username)) {
                throw new IllegalArgumentException("Username already taken");
            }
            String hash = m_encoder.encode(req.password().getValue());
            m_users.add(new UserAccount(username, hash, UserAccount.Role.TRIAL));
            LOGGER.info("event=user_registered username={}", username);
            return ResponseEntity.ok("{\"success\":true}");
        } catch (Exception ex) {
            LOGGER.warn("event=registration_failed username={} reason={}", req.username().getValue(), ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("{\"error\":\"" + ex.getMessage() + "\"}");
        }
    }

    /**
     * GET /gencsrftoken
     * Exposed so the login page can prime a CSRF cookie before the first POST.
     * Spring Security's CookieCsrfTokenRepository will set the XSRF-TOKEN cookie.
     */
    @GetMapping("/gencsrftoken")
    public ResponseEntity<Void> generateCsrfToken() {
        return ResponseEntity.ok().build();
    }
}
