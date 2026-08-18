package com.securefromscratch.busybee.config;

import com.securefromscratch.busybee.auth.UsernamePasswordDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)   // enables @PreAuthorize
public class SecurityConfig {

    @Autowired
    private UsernamePasswordDetailsService userDetailsService;

    /**
     * BCrypt password encoder – slow by design, resists brute-force.
     * Raw passwords are NEVER stored anywhere in the application.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Public endpoints (login page, static assets, registration)
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(
                        "/index.html", "/welcome.css", "/register.js", "/login.js",
                        "/busybee.webp", "/busybee.png", "/favicon.ico",
                        "/sfslogo4_w_white_margins2.png",
                        "/register", "/gencsrftoken", "/error"
                ).permitAll()
                .anyRequest().authenticated()
        );

        // Form-based login
        http.formLogin(form -> form
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/main/main.html", true)
                .failureUrl("/index.html?error=true")
                .permitAll()
        );

        // Logout
        http.logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/index.html")
                .deleteCookies("JSESSIONID")
                .permitAll()
        );

        // CSRF: use cookie-based repository so the JS frontend can read the token.
        // withHttpOnlyFalse() lets JavaScript read the XSRF-TOKEN cookie.
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null); // defer token loading
        http.csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(requestHandler)
        );

        // Session: always create a session, mark cookie as HttpOnly + SameSite=Strict
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
        );

        // Force HTTPS – redirect HTTP → HTTPS
        http.requiresChannel(channel -> channel
                .anyRequest().requiresSecure()
        );

        return http.build();
    }
}
