package com.securefromscratch.busybee.auth;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class UsersStorage {
    private final Map<String, UserAccount> m_users = new ConcurrentHashMap<>();

    public void add(UserAccount account) {
        m_users.put(account.getUsername(), account);
    }

    public Optional<UserAccount> findByUsername(String username) {
        return Optional.ofNullable(m_users.get(username));
    }

    public boolean exists(String username) {
        return m_users.containsKey(username);
    }
}
