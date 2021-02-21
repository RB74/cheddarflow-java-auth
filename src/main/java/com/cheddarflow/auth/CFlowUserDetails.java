package com.cheddarflow.auth;

import com.cheddarflow.model.CognitoUser;
import com.cheddarflow.model.Permission;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CFlowUserDetails implements UserDetails {

    private CognitoUser cognitoUser;
    private String bcryptPassword;

    public CFlowUserDetails(CognitoUser cognitoUser, final String bcryptPassword) {
        this.cognitoUser = cognitoUser;
        this.bcryptPassword = bcryptPassword;
    }

    public CFlowUserDetails(CognitoUser user) {
        this(user, "{bcrypt}" + new BCryptPasswordEncoder().encode(user.getCredentials().getPassword()));
    }

    public CognitoUser getCognitoUser() {
        return this.cognitoUser;
    }

    public void setCognitoUser(CognitoUser cognitoUser) {
        this.cognitoUser = cognitoUser;
        this.bcryptPassword = "{bcrypt}" + new BCryptPasswordEncoder().encode(cognitoUser.getCredentials().getPassword());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (this.cognitoUser.getPermission() == Permission.PROFESSIONAL) {
            return Arrays.asList(new SimpleGrantedAuthority(Permission.PROFESSIONAL.name()),
              new SimpleGrantedAuthority(Permission.STANDARD.name()));
        }
        return Collections.singletonList(new SimpleGrantedAuthority(Permission.STANDARD.name()));
    }

    @Override
    public String getPassword() {
        return this.bcryptPassword;
    }

    @Override
    public String getUsername() {
        return this.cognitoUser.getCredentials().getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
