package com.motomark.digital_signing_example.config;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.*;

import com.motomark.digital_signing_example.filter.SignatureAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final SignatureAuthenticationFilter signatureFilter;

    public SecurityConfig(SignatureAuthenticationFilter signatureFilter) {
        this.signatureFilter = signatureFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated())
                .addFilterBefore(signatureFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
