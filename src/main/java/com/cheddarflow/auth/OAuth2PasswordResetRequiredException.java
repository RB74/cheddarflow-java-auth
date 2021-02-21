package com.cheddarflow.auth;

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;

public class OAuth2PasswordResetRequiredException extends ClientAuthenticationException {

    public OAuth2PasswordResetRequiredException(String msg, Throwable t) {
        super(msg, t);
    }

    public OAuth2PasswordResetRequiredException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return "password_reset_required";
    }
}
