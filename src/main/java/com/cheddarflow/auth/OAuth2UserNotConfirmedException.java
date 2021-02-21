package com.cheddarflow.auth;

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;

public class OAuth2UserNotConfirmedException extends ClientAuthenticationException {

    public OAuth2UserNotConfirmedException(String msg, Throwable t) {
        super(msg, t);
    }

    public OAuth2UserNotConfirmedException(String msg) {
        super(msg);
    }

    @Override
    public String getOAuth2ErrorCode() {
        return "user_not_confirmed";
    }
}
