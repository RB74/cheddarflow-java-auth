package com.cheddarflow.auth;

import com.cheddarflow.model.CognitoUser;
import com.cheddarflow.model.Credentials;

import java.util.Objects;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Service
public class CognitoAuthenticationManager implements UserDetailsService {

    private final CognitoAuthorityManager cognitoAuthorityManager;
    private final PermissionsService permissionsService;

    @Autowired
    public CognitoAuthenticationManager(CognitoAuthorityManager cognitoAuthorityManager,
      PermissionsService permissionsService) {
        this.cognitoAuthorityManager = cognitoAuthorityManager;
        this.permissionsService = permissionsService;
    }

    private UserDetails loadUserByUsername(String username, String password) {
        if (password == null && Objects.equals("refresh_token", getHttpServletRequest().getParameter("grant_type"))) {
            final Credentials credentials = new Credentials(username, "");
            final CognitoUser user = this.cognitoAuthorityManager.getUser(username);
            user.setCredentials(credentials);
            final String idToken = getHttpServletRequest().getParameter("id_token");
            if (idToken != null && !idToken.isBlank()) {
                user.setIdToken(idToken);
                user.setPermission(this.permissionsService.getPermission(idToken));
            }
            return new CFlowUserDetails(user);
        }
        final Credentials credentials = new Credentials(username, password);
        try {
            final CognitoUser user = this.cognitoAuthorityManager.login(credentials);
            if (user == null)
                throw new UsernameNotFoundException("Failed to authenticate `" + username + "'");
            user.setCredentials(credentials);
            return new CFlowUserDetails(user);
        } catch (Exception e) {
            if (e instanceof AuthenticationException || e instanceof OAuth2Exception)
                throw e;
            throw new UsernameNotFoundException("Failed to authenticate `" + username + "'", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        final HttpServletRequest request = this.getHttpServletRequest();
        return this.loadUserByUsername(username, this.getPasswordFromRequest(request));
    }

    private HttpServletRequest getHttpServletRequest() {
        ServletRequestAttributes attributes = (ServletRequestAttributes)RequestContextHolder.currentRequestAttributes();
        return attributes.getRequest();
    }

    private String getPasswordFromRequest(HttpServletRequest request) {
        return Optional.ofNullable(request.getParameter("password"))
          .orElse(Optional.ofNullable(request.getAttribute("password")).map(Object::toString).orElse(null));
    }
}
