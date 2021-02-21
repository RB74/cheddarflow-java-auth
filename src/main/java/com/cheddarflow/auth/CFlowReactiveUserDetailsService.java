package com.cheddarflow.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Mono;

@Service
public class CFlowReactiveUserDetailsService implements ReactiveUserDetailsService {

    private final CFlowTokenLoadingAuthenticationManager authenticationManager;

    @Autowired
    public CFlowReactiveUserDetailsService(CFlowTokenLoadingAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        return Mono.justOrEmpty(this.authenticationManager.loadUserByUsername(username));
    }
}
