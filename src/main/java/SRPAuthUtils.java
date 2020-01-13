import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

public class SRPAuthUtils {

    private static final String HEX_N =
      "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
    private static final BigInteger N = new BigInteger(HEX_N, 16);
    private static final BigInteger g = BigInteger.valueOf(2);
    private static final BigInteger k;
    private static final int EPHEMERAL_KEY_LENGTH = 1024;
    private static final int DERIVED_KEY_SIZE = 16;
    private static final String DERIVED_KEY_INFO = "Caldera Derived Key";
    private static final SecureRandom SECURE_RANDOM;

    private static final String UTF8 = "UTF-8";
    private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST =
      new ThreadLocal<>() {
          @Override
          protected MessageDigest initialValue() {
              try {
                  return MessageDigest.getInstance("SHA-256");
              } catch (NoSuchAlgorithmException e) {
                  throw new SecurityException("Exception in authentication", e);
              }
          }
      };
    private static BigInteger a;
    private static BigInteger A;

    static {
        try {
            SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

            MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
            messageDigest.reset();
            messageDigest.update(N.toByteArray());
            byte[] digest = messageDigest.digest(g.toByteArray());
            k = new BigInteger(1, digest);
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }

        do {
            a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
            A = g.modPow(a, N);
        } while (A.mod(N).equals(BigInteger.ZERO));

    }

    public static BigInteger getA() {
        return A;
    }

    public static Map<String, String> generateInitiateAuthParameters(String username) {

        Map<String, String> authParameters = new HashMap<>();

        authParameters.put("USERNAME", username);
        authParameters.put("SRP_A", A.toString(16));

        return authParameters;
    }

    public static Map<String, String> generateAuthResponse(String userIdForSRP, String srpB, String saltString,
                                                           String secretBlockString, String userPoolId, String password,
                                                           String username) throws UnsupportedEncodingException {

        BigInteger B = new BigInteger(srpB, 16);
        if (B.mod(N).equals(BigInteger.ZERO)) {
            throw new SecurityException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(saltString, 16);
        byte[] key = getPasswordAuthenticationKey(userPoolId, userIdForSRP, password, B, salt);

        Date timestamp = new Date();
        byte[] hmac = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            mac.update(userPoolId.split("_", 2)[1].getBytes(UTF8));
            mac.update(userIdForSRP.getBytes(UTF8));
            byte[] secretBlock = Base64.getDecoder().decode(secretBlockString);
            mac.update(secretBlock);
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
            String dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes(UTF8);
            hmac = mac.doFinal(dateBytes);
        } catch (Exception e) {
            System.out.println(e);
        }

        SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new HashMap<>();
        srpAuthResponses.put("PASSWORD_CLAIM_SECRET_BLOCK", secretBlockString);
        srpAuthResponses.put("PASSWORD_CLAIM_SIGNATURE", Base64.getEncoder().encodeToString(hmac));
        srpAuthResponses.put("TIMESTAMP", formatTimestamp.format(timestamp));
        srpAuthResponses.put("USERNAME", username);

        return srpAuthResponses;

    }

    private static byte[] getPasswordAuthenticationKey(String userPoolId,
                                                       String userId,
                                                       String userPassword,
                                                       BigInteger B,
                                                       BigInteger salt) throws UnsupportedEncodingException {
        // Authenticate the password
        // u = H(A, B)
        MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
        messageDigest.reset();
        messageDigest.update(A.toByteArray());
        BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
        if (u.equals(BigInteger.ZERO)) {
            throw new SecurityException("Hash of A and B cannot be zero");
        }

        // x = H(salt | H(poolName | userId | ":" | password))
        messageDigest.reset();
        messageDigest.update(userPoolId.split("_", 2)[1].getBytes(UTF8));
        messageDigest.update(userId.getBytes(UTF8));
        messageDigest.update(":".getBytes(UTF8));
        byte[] userIdHash = messageDigest.digest(userPassword.getBytes(UTF8));

        messageDigest.reset();
        messageDigest.update(salt.toByteArray());
        BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
        BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

        HashKeyDerivationFunctionUtils hkdf;
        try {
            hkdf = HashKeyDerivationFunctionUtils.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            throw new SecurityException(e.getMessage(), e);
        }
        hkdf.init(S.toByteArray(), u.toByteArray());
        byte[] key = hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
        return key;
    }

}
