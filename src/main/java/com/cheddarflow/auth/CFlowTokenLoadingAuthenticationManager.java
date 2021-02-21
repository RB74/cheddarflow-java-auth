package com.cheddarflow.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractUserDetailsReactiveAuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Mono;

@Service
public class CFlowTokenLoadingAuthenticationManager extends AbstractUserDetailsReactiveAuthenticationManager
  implements UserDetailsService {

    private final ResourceServerTokenServices resourceServerTokenServices;

    @Autowired
    public CFlowTokenLoadingAuthenticationManager(ResourceServerTokenServices resourceServerTokenServices) {
        this.resourceServerTokenServices = resourceServerTokenServices;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final OAuth2Authentication authentication = this.resourceServerTokenServices.loadAuthentication(username);
        final CFlowUserDetails cFlowUserDetails =  (CFlowUserDetails)authentication.getUserAuthentication().getPrincipal();
        cFlowUserDetails.getCognitoUser().getCredentials().setPassword(username);
        return new CFlowUserDetails(cFlowUserDetails.getCognitoUser());
    }

    @Override
    protected Mono<UserDetails> retrieveUser(String username) {
        return Mono.justOrEmpty(this.loadUserByUsername(username));
    }
}
