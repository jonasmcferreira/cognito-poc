import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.Map;

import static software.amazon.awssdk.services.cognitoidentityprovider.model.AuthFlowType.USER_SRP_AUTH;

public class CognitoAuthenticator {

    private static CognitoIdentityProviderClient cognitoUserPoolClient;

    public static void main(String[] args) throws UnsupportedEncodingException {
        cognitoUserPoolClient = CognitoIdentityProviderClient.builder()
          .region(Region.of("eu-central-1"))
          .build();

        String userPoolId = args[0];
        String clientAppId = args[1];

        String token = performSRPAuthentication(clientAppId, userPoolId, args[2], args[3]);
        System.out.println(token);
    }

    private static String performSRPAuthentication(String clientAppId,
                                           String userPoolId,
                                           String username,
                                           String password) throws UnsupportedEncodingException {

        AwsCredentials anonymousCredentials = new AwsCredentials() {
            @Override
            public String accessKeyId() {
                return null;
            }

            @Override
            public String secretAccessKey() {
                return null;
            }
        };

        CognitoIdentityProviderClient cognitoclient =
          CognitoIdentityProviderClient.builder()
            .credentialsProvider(StaticCredentialsProvider.create(anonymousCredentials))
            .region(Region.EU_CENTRAL_1)
            .build();

        Map<String, String> authParameters = SRPAuthUtils.generateInitiateAuthParameters(username);

        InitiateAuthResponse initiateAuthResponse = cognitoclient.initiateAuth(
          InitiateAuthRequest.builder()
            .authFlow(USER_SRP_AUTH)
            .clientId(clientAppId)
            .authParameters(authParameters)
            .build()
        );

        String userIdForSRP = initiateAuthResponse.challengeParameters().get("USER_ID_FOR_SRP");
        String srpB = initiateAuthResponse.challengeParameters().get("SRP_B");
        String saltString = initiateAuthResponse.challengeParameters().get("SALT");
        String secretBlock = initiateAuthResponse.challengeParameters().get("SECRET_BLOCK");


        Map<String, String> srpAuthResponses = SRPAuthUtils.generateAuthResponse(userIdForSRP, srpB,
          saltString, secretBlock, userPoolId, password, username);

        final RespondToAuthChallengeResponse challengeResponse = cognitoclient.respondToAuthChallenge(
          RespondToAuthChallengeRequest.builder()
            .challengeName(initiateAuthResponse.challengeName())
            .clientId(clientAppId)
            .session(initiateAuthResponse.session())
            .challengeResponses(srpAuthResponses)
            .build()
        );

        return challengeResponse.authenticationResult().idToken();

    }

}
