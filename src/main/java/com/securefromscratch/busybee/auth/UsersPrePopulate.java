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
		createUser("admin",   UserAccount.Role.ADMIN);
		createUser("alice",   UserAccount.Role.CREATOR);
		createUser("bob",     UserAccount.Role.CREATOR);
		createUser("charlie", UserAccount.Role.TRIAL);
		LOGGER.info("event=users_prepopulated count=4");
	}

	private void createUser(String username, UserAccount.Role role) {
		String plainPwd = java.util.UUID.randomUUID().toString().substring(0, 12);
		String encoded  = m_encoder.encode(plainPwd);
		m_users.add(new UserAccount(username, encoded, role));
		LOGGER.info("event=user_created username={} tempPassword={}", username, plainPwd);
	}
}
