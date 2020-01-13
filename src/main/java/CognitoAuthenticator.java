import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

public class CognitoAuthenticator {

    public static void main(String[] args){
        CognitoIdentityProviderClient cognitoUserPoolClient = CognitoIdentityProviderClient.builder()
          .region(Region.of("eu-central-1"))
          .build();


    }
}
