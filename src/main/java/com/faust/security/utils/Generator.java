package com.faust.security.utils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import com.faust.security.exception.SecurityException;
import com.faust.security.secret.SensitiveWork;

public final class Generator {
    private Generator() {}

    /**
     * Is not performant and should not be used for very large array sizes (as in hundreds of thousands).
     * Is not truly random and it is not secure. Use only for non-security, non-critical operations.
     */
    public static int[] generateRandomUniqueArray(final int size, final int boundsMax) {
        final Set<Integer> set = new HashSet<>();
        final Random random = new Random();

        if (size > boundsMax + 1) {
            throw new IllegalArgumentException("Max bounds cannot be lower than the expected size of the array.");
        }
        while (set.size() < size) {
            final int randomNumber = random.nextInt(boundsMax + 1);
            set.add(randomNumber);
        }
        return set.stream().mapToInt(Integer::intValue).toArray();
    }

    /**
     * Generates a char array of a given size using a strong instance of SecureRandom and encodes it
     * with a Base64 URL safe encoding scheme.
     * <b>WARNING: this is not intended for later decoding with Base64 (there is nothing to decode anyway)!
     * It can in fact fail if a valid Base64 size is not chosen since we are reducing the array
     * if it does not fit the target size.</b>
     */
    public static char[] generateSecureRandomUrlSafeCharArray(final int arraySize) throws SecurityException {
        final int byteSize = CharUtils.unpaddedBase64SizeToByteSize(arraySize);
        return SensitiveWork.destroyAfterWork(secrets -> {
            final byte[] bytes = generateSecureRandomBytes(byteSize);
            final char[] encoded = CharUtils.convertAndDestroyBytesToChars(CharUtils.base64EncodeAndDestroyBytesToBytes(bytes));

            if (encoded.length != arraySize) {
                secrets.addSecret(encoded);
                final char[] reducedArray = new char[arraySize];
                System.arraycopy(encoded, 0, reducedArray, 0,arraySize);
                return reducedArray;
            }
            return encoded;
        });
    }

    public static byte[] generateSecureRandomBytes(final int size) throws SecurityException {
        if (size < 0) {
            throw new IllegalArgumentException("Argument size cannot be negative.");
        }
        final byte[] bytes = new byte[size];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
            return bytes;
        }
        catch (final NoSuchAlgorithmException e) {
            throw new SecurityException(e);
        }
    }
}
