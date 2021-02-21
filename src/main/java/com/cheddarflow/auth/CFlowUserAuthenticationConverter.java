package com.cheddarflow.auth;

import com.cheddarflow.model.CognitoUser;
import com.cheddarflow.model.Permission;

import java.util.Map;
import java.util.Optional;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

public class CFlowUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    private final CognitoUserProvider userProvider;

    public CFlowUserAuthenticationConverter(CognitoUserProvider userProvider) {
        this.userProvider = userProvider;
    }

    public Authentication extractAuthentication(Map<String, ?> map) {
        if (map.containsKey("user_name")) {
            final String username = (String)map.get("user_name");
            final CognitoUser user = this.userProvider.findByUsername(username);
            user.setAccessToken((String)map.get("cognito_access_token"));
            user.setRefreshToken((String)map.get("cognito_refresh_token"));
            user.setIdToken((String)map.get("id_token"));
            user.setPermission(Permission.valueOf(Optional.ofNullable((String)map.get("permission")).orElse("STANDARD")));
            final CFlowUserDetails userDetails = new CFlowUserDetails(user);
            return new UsernamePasswordAuthenticationToken(userDetails, "N/A", userDetails.getAuthorities());
        }
        return super.extractAuthentication(map);
    }
}
