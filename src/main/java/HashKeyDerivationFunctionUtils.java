import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HashKeyDerivationFunctionUtils {

    private static final int MAX_KEY_SIZE = 255;
    private static final String UTF8 = "UTF-8";
    private final byte[] EMPTY_ARRAY = new byte[0];
    private final String algorithm;
    private SecretKey prk = null;

    private HashKeyDerivationFunctionUtils(String algorithm) {
        if (!algorithm.startsWith("Hmac")) {
            throw new IllegalArgumentException("Invalid algorithm " + algorithm
              + ". Hkdf may only be used with Hmac algorithms.");
        } else {
            this.algorithm = algorithm;
        }
    }

    /**
     * Static initializer
     *
     * @param algorithm REQUIRED: The type of HMAC algorithm to be used.
     */
    public static HashKeyDerivationFunctionUtils getInstance(String algorithm) throws NoSuchAlgorithmException {

        return new HashKeyDerivationFunctionUtils(algorithm);
    }

    /**
     * @param ikm REQUIRED: The input key material.
     */
    public void init(byte[] ikm) {
        init(ikm, (byte[]) null);
    }

    /**
     * @param ikm REQUIRED: The input key material.
     * @param salt REQUIRED: Random bytes for salt.
     */
    public void init(byte[] ikm, byte[] salt) {
        byte[] realSalt = salt == null ? EMPTY_ARRAY : (byte[]) salt.clone();
        byte[] rawKeyMaterial = EMPTY_ARRAY;

        try {
            final Mac e = Mac.getInstance(algorithm);
            if (realSalt.length == 0) {
                realSalt = new byte[e.getMacLength()];
                Arrays.fill(realSalt, (byte) 0);
            }

            e.init(new SecretKeySpec(realSalt, algorithm));
            rawKeyMaterial = e.doFinal(ikm);
            final SecretKeySpec key = new SecretKeySpec(rawKeyMaterial, algorithm);
            Arrays.fill(rawKeyMaterial, (byte) 0);
            unsafeInitWithoutKeyExtraction(key);
        } catch (final GeneralSecurityException var10) {
            throw new RuntimeException("Unexpected exception", var10);
        } finally {
            Arrays.fill(rawKeyMaterial, (byte) 0);
        }

    }

    /**
     * @param rawKey REQUIRED: Current secret key.
     *
     * @throws InvalidKeyException
     */
    private void unsafeInitWithoutKeyExtraction(SecretKey rawKey) throws InvalidKeyException {
        if (!rawKey.getAlgorithm().equals(algorithm)) {
            throw new InvalidKeyException(
              "Algorithm for the provided key must match the algorithm for this Hkdf. Expected "
                + algorithm + " but found " + rawKey.getAlgorithm());
        } else {
            prk = rawKey;
        }
    }

    /**
     * @param info REQUIRED
     * @param length REQUIRED
     *
     * @return converted bytes.
     */
    public byte[] deriveKey(String info, int length) throws UnsupportedEncodingException {
        return deriveKey(info != null ? info.getBytes(UTF8) : null, length);
    }

    /**
     * @param info REQUIRED
     * @param length REQUIRED
     *
     * @return converted bytes.
     */
    private byte[] deriveKey(byte[] info, int length) {
        final byte[] result = new byte[length];

        try {
            deriveKey(info, length, result, 0);
            return result;
        } catch (final ShortBufferException var5) {
            throw new RuntimeException(var5);
        }
    }

    /**
     * @param info REQUIRED
     * @param length REQUIRED
     * @param output REQUIRED
     * @param offset REQUIRED
     *
     * @throws ShortBufferException
     */
    private void deriveKey(byte[] info, int length, byte[] output, int offset)
      throws ShortBufferException {
        assertInitialized();
        if (length < 0) {
            throw new IllegalArgumentException("Length must be a non-negative value.");
        } else if (output.length < offset + length) {
            throw new ShortBufferException();
        } else {
            final Mac mac = createMac();
            if (length > MAX_KEY_SIZE * mac.getMacLength()) {
                throw new IllegalArgumentException(
                  "Requested keys may not be longer than 255 times the underlying HMAC length.");
            } else {
                byte[] t = EMPTY_ARRAY;

                try {
                    int loc = 0;

                    for (byte i = 1; loc < length; ++i) {
                        mac.update(t);
                        mac.update(info);
                        mac.update(i);
                        t = mac.doFinal();

                        for (int x = 0; x < t.length && loc < length; ++loc) {
                            output[loc] = t[x];
                            ++x;
                        }
                    }
                } finally {
                    Arrays.fill(t, (byte) 0);
                }

            }
        }
    }

    /**
     * Checks for a valid pseudo-random key.
     */
    private void assertInitialized() {
        if (prk == null) {
            throw new IllegalStateException("Hkdf has not been initialized");
        }
    }

    /**
     * @return the generates message authentication code.
     */
    private Mac createMac() {
        try {
            final Mac ex = Mac.getInstance(algorithm);
            ex.init(prk);
            return ex;
        } catch (final NoSuchAlgorithmException var2) {
            throw new RuntimeException(var2);
        } catch (final InvalidKeyException var3) {
            throw new RuntimeException(var3);
        }
    }

}
