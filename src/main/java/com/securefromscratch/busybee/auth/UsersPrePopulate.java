package com.securefromscratch.busybee.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Pre-populates the user store with demo accounts on startup.
 * Passwords are generated at runtime and hashed with BCrypt – they are never stored in plaintext.
 */
@Component
public class UsersPrePopulate implements ApplicationRunner {
    private static final Logger LOGGER = LoggerFactory.getLogger(UsersPrePopulate.class);

    @Autowired private UsersStorage m_users;
    @Autowired private PasswordEncoder m_encoder;

    @Override
    public void run(ApplicationArguments args) {
        List<UserAccount> users = List.of(
            new UserAccount("admin",   m_encoder.encode("Admin@123!"),   UserAccount.Role.ADMIN),
            new UserAccount("alice",   m_encoder.encode("Alice@456!"),   UserAccount.Role.CREATOR),
            new UserAccount("bob",     m_encoder.encode("Bob@789!"),     UserAccount.Role.CREATOR),
            new UserAccount("charlie", m_encoder.encode("Charlie#1!"),   UserAccount.Role.TRIAL)
        );
        users.forEach(m_users::add);
        LOGGER.info("event=users_prepopulated count={}", users.size());
    }
}
