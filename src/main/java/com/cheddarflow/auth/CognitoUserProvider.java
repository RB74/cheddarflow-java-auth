package com.cheddarflow.auth;

import com.cheddarflow.model.CognitoUser;

@FunctionalInterface
public interface CognitoUserProvider {

    CognitoUser findByUsername(String username);
}
