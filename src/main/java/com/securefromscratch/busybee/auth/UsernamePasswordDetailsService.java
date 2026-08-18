package com.securefromscratch.busybee.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UsernamePasswordDetailsService implements UserDetailsService {
    private static final Logger LOGGER = LoggerFactory.getLogger(UsernamePasswordDetailsService.class);

    @Autowired
    private UsersStorage m_users;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails userDetails = m_users.findByUsername(username)
                .orElseThrow(() -> {
                    LOGGER.warn("event=login_failed reason=user_not_found");
                    return new UsernameNotFoundException("User not found: " + username);
                });
        LOGGER.info("event=login_success username={}", userDetails.getUsername());
        return userDetails;
    }
}
