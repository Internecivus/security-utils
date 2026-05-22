package com.faust.security;

import com.faust.security.cryptography.CryptographyConfiguration;
import com.faust.security.exception.InvalidConfigurationException;

public class TestUtils {
    public static char[] getEmptyCharArray() {
        return new char[0];
    }

    public static byte[] getEmptyByteArray() {
        return new byte[0];
    }

    public static class TestConfiguration1 {
        public static int ITERATIONS = 49999;
        public static String HASH_ALGORITHM = "PBKDF2WithHmacSHA1";
        public static char HASH_PART_DELIMITER = '/';
        public static int KEY_BYTE_SIZE = 28;
        public static int MAXIMUM_PASSWORD_SIZE = 64;
    }

    public static CryptographyConfiguration getTestConfiguration1WithoutPepper() throws InvalidConfigurationException {
       return new CryptographyConfiguration(
               TestConfiguration1.ITERATIONS,
               TestConfiguration1.HASH_ALGORITHM,
               TestConfiguration1.HASH_PART_DELIMITER,
               TestConfiguration1.KEY_BYTE_SIZE,
               TestConfiguration1.MAXIMUM_PASSWORD_SIZE
       );
    }

    public static CryptographyConfiguration getTestConfiguration1WithPepper() throws InvalidConfigurationException {
        return new CryptographyConfiguration(
                TestConfiguration1.ITERATIONS,
                TestConfiguration1.HASH_ALGORITHM,
                TestConfiguration1.HASH_PART_DELIMITER,
                TestConfiguration1.KEY_BYTE_SIZE,
                TestConfiguration1.MAXIMUM_PASSWORD_SIZE,
                true
        );
    }

    public static boolean isDestroyed(final char[][] charsArray) {
        for (final char[] chars : charsArray) {
            if (!isDestroyed(chars)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isDestroyed(final byte[][] bytesArray) {
        for (final byte[] bytes : bytesArray) {
            if (!isDestroyed(bytes)) {
                return false;
            }
        }
        return true;
    }

    public static boolean isDestroyed(final char[] chars) {
        if (chars == null) {
            return true;
        }
        boolean isDestroyed = true;
        for (final char element : chars) {
            if (element != '\u0000') {
                isDestroyed = false;
                break;
            }
        }
        return isDestroyed;
    }

    public static boolean isDestroyed(final byte[] bytes) {
        if (bytes == null) {
            return true;
        }
        boolean isDestroyed = true;
        for (final byte element : bytes) {
            if (element != (byte) 0) {
                isDestroyed = false;
                break;
            }
        }
        return isDestroyed;
    }
}
