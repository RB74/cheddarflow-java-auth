package com.cheddarflow.auth;

import com.cheddarflow.model.CognitoUser;
import com.cheddarflow.model.Credentials;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminInitiateAuthResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminResetUserPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRespondToAuthChallengeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminRespondToAuthChallengeResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ChallengeNameType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmForgotPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmSignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ConfirmSignUpResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ForgotPasswordRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.GetUserAttributeVerificationCodeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.PasswordResetRequiredException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ResendConfirmationCodeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.SignUpRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UpdateUserAttributesRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotConfirmedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.VerifyUserAttributeRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.VerifyUserAttributeResponse;

@Service
public class CognitoAuthorityManager {
    private final String appClientId = Optional.ofNullable(System.getenv("AWS_COGNITO_APP_CLIENT_ID"))
      .orElse(System.getProperty("AWS_COGNITO_APP_CLIENT_ID"));
    private final String userPoolId = Optional.ofNullable(System.getenv("AWS_COGNITO_USER_POOL_ID"))
      .orElse(System.getProperty("AWS_COGNITO_USER_POOL_ID"));
    private final CognitoIdentityProviderClient cognito;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final PermissionsService permissionsService;

    @Autowired
    public CognitoAuthorityManager(PermissionsService permissionsService) {
        this.permissionsService = permissionsService;
        String region = Optional.ofNullable(System.getenv("AWS_DEFAULT_REGION"))
          .orElse(System.getProperty("AWS_DEFAULT_REGION", "us-east-2"));
        this.cognito = CognitoIdentityProviderClient.builder().region(Region.of(region)).build();
    }

    public CognitoUser getUser(String username) {

        AdminGetUserRequest req = AdminGetUserRequest.builder()
          .userPoolId(userPoolId)
          .username(username)
          .build();
        AdminGetUserResponse result = cognito.adminGetUser(req);

        CognitoUser u = new CognitoUser();
        u.getCredentials().setUsername(username);
        u.getCredentials().setPassword("");
        processUserAttributes(u, result.userAttributes());

        return u;
    }

    public CognitoUser refreshTokens(String username, String refreshToken) {
        final Map<String, String> authParams = new HashMap<>(1);
        authParams.put("REFRESH_TOKEN", refreshToken);

        final AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
          .clientId(appClientId)
          .userPoolId(userPoolId)
          .authFlow(AuthFlowType.REFRESH_TOKEN_AUTH)
          .authParameters(authParams)
          .build();

        AdminInitiateAuthResponse result;

        try {
            result = cognito.adminInitiateAuth(authRequest);
        } catch (CognitoIdentityProviderException e) {
            this.logger.error("Error refreshing tokens", e);
            return null;
        }

        if (result.authenticationResult().accessToken() == null) {
            throw new RuntimeException("Invalid credentials");
        }

        CognitoUser u = getUser(username);
        u.setAccessToken(result.authenticationResult().accessToken());
        u.setRefreshToken(refreshToken);
        u.setIdToken(result.authenticationResult().idToken());
        return u;
    }


    public CognitoUser login(Credentials c) {
        return login(c, c.getPassword());
    }

    public CognitoUser login(Credentials c, String newPassword) {
        final Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", c.getUsername());
        authParams.put("PASSWORD", c.getPassword());

        final AdminInitiateAuthRequest authRequest = AdminInitiateAuthRequest.builder()
          .authFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
          .clientId(appClientId)
          .userPoolId(userPoolId)
          .authParameters(authParams)
          .build();

        AdminInitiateAuthResponse result;

        try {
            result = cognito.adminInitiateAuth(authRequest);
        } catch (PasswordResetRequiredException e) {
            //cognito.forgotPassword(ForgotPasswordRequest.builder().clientId(appClientId).username(c.getUsername()).build());
            throw new OAuth2PasswordResetRequiredException("Password reset required");
        } catch (UserNotConfirmedException e) {
            throw new OAuth2UserNotConfirmedException("User not confirmed");
        } catch (CognitoIdentityProviderException e) {
            this.logger.error("Error logging in", e);
            return null;
        }

        AuthenticationResultType authResult;

        // Has a Challenge
        if (result.challengeName() != null && result.challengeName() == ChallengeNameType.NEW_PASSWORD_REQUIRED) {
            // we still need the username
            final Map<String, String> challengeResponses = new HashMap<>();
            challengeResponses.put("USERNAME", c.getUsername());
            challengeResponses.put("PASSWORD", c.getPassword());
            challengeResponses.put("NEW_PASSWORD", newPassword);

            // populate the challenge response
            final AdminRespondToAuthChallengeRequest request = AdminRespondToAuthChallengeRequest.builder()
              .challengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
              .challengeResponses(challengeResponses)
              .clientId(appClientId)
              .userPoolId(userPoolId)
              .session(result.session())
              .build();

            AdminRespondToAuthChallengeResponse resultChallenge = cognito.adminRespondToAuthChallenge(request);
            authResult = resultChallenge.authenticationResult();
        } else {
            authResult = result.authenticationResult();
        }

        if (authResult.accessToken() == null) {
            throw new RuntimeException("Invalid credentials");
        }

        CognitoUser u = getUser(c.getUsername());
        u.setAccessToken(authResult.accessToken());
        u.setRefreshToken(authResult.refreshToken());
        u.setIdToken(authResult.idToken());
        u.setPermission(this.permissionsService.getPermission(authResult.idToken()));

        return u;
    }

    public void signup(CognitoUser u) {
        SignUpRequest request = SignUpRequest.builder()
          .clientId(appClientId)
          .username(u.getCredentials().getUsername())
          .userAttributes(AttributeType.builder()
            .name("email")
            .value(u.getEmail())
            .build(),
            AttributeType.builder()
              .name("name")
              .value(u.getName())
              .build(),
            AttributeType.builder()
              .name("family_name")
              .value(u.getLastName())
              .build(),
            AttributeType.builder()
              .name("phone_number")
              .value(u.getPhoneNumber())
              .build(),
            AttributeType.builder()
              .name("custom:score")
              .value(u.getScore())
              .build(),
            AttributeType.builder()
              .name("custom:plan")
              .value(u.getPlan())
              .build())
          .password(u.getCredentials().getPassword())
          .build();
        this.cognito.signUp(request);
    }

    public void update(CognitoUser u) {
        UpdateUserAttributesRequest.Builder request = UpdateUserAttributesRequest.builder()
          .accessToken(u.getAccessToken());
        final List<AttributeType> userAttributes = new ArrayList<>();
        if (u.getName() != null) {
            userAttributes.add(
              AttributeType.builder()
                .name("name")
                .value(u.getName())
              .build());
        }

        if (u.getLastName() != null) {
            userAttributes.add(
              AttributeType.builder()
                .name("family_name")
                .value(u.getLastName())
                .build());
        }

        if (u.getPhoneNumber() != null) {
            userAttributes.add(
              AttributeType.builder()
                .name("phone_number")
                .value(u.getPhoneNumber())
                .build());
        }

        this.cognito.updateUserAttributes(request.userAttributes(userAttributes).build());
    }

    public CognitoUser updatePassword(CognitoUser u, String newPassword) {
        u = login(u.getCredentials());
        if (u == null) return null;

        AdminResetUserPasswordRequest request = AdminResetUserPasswordRequest.builder()
          .userPoolId(userPoolId)
          .username(u.getCredentials().getUsername())
          .build();
        cognito.adminResetUserPassword(request);

        return login(u.getCredentials(), newPassword);
    }

    public void sendConfirmationCode(String username) {
        this.cognito.resendConfirmationCode(ResendConfirmationCodeRequest.builder()
          .clientId(appClientId)
          .username(username)
          .build());
    }

    public boolean confirmUser(String username, String code) {
        ConfirmSignUpRequest req = ConfirmSignUpRequest.builder()
          .clientId(appClientId)
          .confirmationCode(code)
          .username(username)
          .build();
        ConfirmSignUpResponse res = cognito.confirmSignUp(req);
        return res != null;
    }

    public void sendForgotPassword(String username) {
        ForgotPasswordRequest req = ForgotPasswordRequest.builder()
          .clientId(appClientId)
          .username(username)
          .build();

        this.cognito.forgotPassword(req);
    }

    public void verifyForgotPassword(String username, String code, String newPassword) {
        ConfirmForgotPasswordRequest req = ConfirmForgotPasswordRequest.builder()
          .clientId(appClientId)
          .username(username)
          .confirmationCode(code)
          .password(newPassword)
          .build();

        this.cognito.confirmForgotPassword(req);
    }

    private void processUserAttributes(CognitoUser u, List<AttributeType> attr) {
        for (AttributeType attribute : attr) {
            switch (attribute.name()) {
            case "email":
                u.setEmail(attribute.value());
                break;
            case "name":
                u.setName(attribute.value());
                break;
            case "family_name":
                u.setLastName(attribute.value());
                break;
            case "phone_number":
                u.setPhoneNumber(attribute.value());
                break;
            case "email_verified":
                u.setEmailVerified(Boolean.parseBoolean(attribute.value()));
                break;
            }
        }
    }

    public boolean verifyUser(String accessToken, String code) {
        VerifyUserAttributeRequest req = VerifyUserAttributeRequest.builder()
          .attributeName("email")
          .accessToken(accessToken)
          .code(code)
          .build();
        VerifyUserAttributeResponse res = this.cognito.verifyUserAttribute(req);
        return res != null;
    }

    public boolean getUserVerificationCode(String accessToken) {
        GetUserAttributeVerificationCodeRequest theRequest = GetUserAttributeVerificationCodeRequest.builder()
          .accessToken(accessToken)
          .attributeName("email")
          .build();
        return this.cognito.getUserAttributeVerificationCode(theRequest) != null;
    }
}
