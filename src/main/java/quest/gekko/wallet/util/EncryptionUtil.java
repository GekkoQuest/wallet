package quest.gekko.wallet.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.security.SecureRandom;
import java.util.Base64;

@UtilityClass
@Slf4j
public class EncryptionUtil {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String generateSecureVerificationCode() {
        final int codeLength = SecurityConstants.VERIFICATION_CODE_LENGTH;
        final int maxValue = (int) Math.pow(10, codeLength) - 1;
        final int code = SECURE_RANDOM.nextInt(maxValue + 1);
        return String.format("%0" + codeLength + "d", code);
    }

    public static byte[] generateSalt() {
        final byte[] salt = new byte[SecurityConstants.SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] generateIV() {
        final byte[] iv = new byte[SecurityConstants.AES_IV_LENGTH];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    public static String encodeBase64(final byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] decodeBase64(final String data) {
        try {
            return Base64.getDecoder().decode(data);
        } catch (final IllegalArgumentException e) {
            log.warn("Invalid Base64 data provided for decoding");
            throw new IllegalArgumentException("Invalid Base64 format", e);
        }
    }

    public static boolean isValidBase64Length(final String data, final int expectedByteLength) {
        if (data == null) {
            return false;
        }

        try {
            final byte[] decoded = decodeBase64(data);
            return decoded.length == expectedByteLength;
        } catch (final IllegalArgumentException e) {
            return false;
        }
    }
}