package com.faust.security.cryptography;

import com.faust.security.exception.InvalidConfigurationException;
import lombok.Getter;
import lombok.NonNull;

import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;

// TODO maybe implement some warning about weak configuration parameters?
public class CryptographyConfiguration {
    private static class Default {
        private final static int ITERATIONS = 49_999;
        private final static String HASH_ALGORITHM = "PBKDF2WithHmacSHA512";
        private final static char HASH_PART_DELIMITER = ':';
        private final static int KEY_BYTE_SIZE = 28;
        private final static int MAXIMUM_PASSWORD_SIZE = 128;
    }

    @Getter
    private final int iterations;
    @Getter
    private final String hashAlgorithm;
    @Getter
    private final char hashPartDelimiter;
    @Getter
    private final int keyByteSize;
    @Getter
    private boolean usePepper;
    @Getter
    private final int maximumPasswordSize;

    private static final char[] base64Url = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };

    private CryptographyConfiguration() throws InvalidConfigurationException {
        this(Default.ITERATIONS, Default.HASH_ALGORITHM, Default.HASH_PART_DELIMITER, Default.KEY_BYTE_SIZE,
                Default.MAXIMUM_PASSWORD_SIZE);
    }

    public CryptographyConfiguration(final int iterations, final int keyByteSize, final int maximumPasswordSize)
            throws InvalidConfigurationException {
        this(iterations, Default.HASH_ALGORITHM, Default.HASH_PART_DELIMITER, keyByteSize, maximumPasswordSize, false);
    }

    public CryptographyConfiguration(final int iterations, final char hashPartDelimiter, final int keyByteSize,
            final int maximumPasswordSize)
            throws InvalidConfigurationException {
        this(iterations, Default.HASH_ALGORITHM, hashPartDelimiter, keyByteSize, maximumPasswordSize, false);
    }

    public CryptographyConfiguration(final int iterations, final @NonNull String hashAlgorithm,
            final char hashPartDelimiter, final int keyByteSize, final int maximumPasswordSize)
            throws InvalidConfigurationException {
        this(iterations, hashAlgorithm, hashPartDelimiter, keyByteSize, maximumPasswordSize, false);
    }

    public CryptographyConfiguration(final int iterations, final @NonNull String hashAlgorithm,
            final char hashPartDelimiter, final int keyByteSize, final int maximumPasswordSize,
            final boolean usePepper) throws InvalidConfigurationException {
        try {
            this.iterations = validateIterations(iterations);
            this.hashAlgorithm = validateHashAlgorithm(hashAlgorithm);
            this.hashPartDelimiter = validateHashPartDelimiter(hashPartDelimiter);
            this.keyByteSize = validateKeyByteSize(keyByteSize);
            this.maximumPasswordSize = validateMaximumPasswordSize(maximumPasswordSize);
            this.usePepper = usePepper;
        }
        catch (final Exception e) {
            throw new InvalidConfigurationException(e);
        }
    }

    private static int validateIterations(final int iterations) {
        if (iterations < 1) {
            throw new IllegalArgumentException("Iterations must be a positive, non-zero number.");
        }
        return iterations;
    }

    private static String validateHashAlgorithm(final String hashAlgorithm) {
        try {
            SecretKeyFactory.getInstance(hashAlgorithm);
            return hashAlgorithm;
        }
        catch (final NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Hash algorithm must be a valid algorithm acceptable by javax.crypto.SecretKeyFactory.");
        }
    }

    private static char validateHashPartDelimiter(final char hashPartDelimiter) {
        if (new String(base64Url).contains(String.valueOf(hashPartDelimiter))) {
            throw new IllegalArgumentException("Hash part delimiter cannot include any characters from the Base64 URL safe alphabet.");
        }
        return hashPartDelimiter;
    }

    private static int validateMaximumPasswordSize(final int maximumPasswordSize) {
        if (maximumPasswordSize < 1) {
            throw new IllegalArgumentException("Maximum password size must be a positive, non-zero number.");
        }
        return maximumPasswordSize;
    }

    private static int validateKeyByteSize(final int keyByteSize) {
        if (keyByteSize < 1) {
            throw new IllegalArgumentException("Size of the key the must be a positive, non-zero number.");
        }
        return keyByteSize;
    }

    /**
     * <b>WARNING: Not recommended for use in production as configuration parameters
     * should be private and difficult to guess.</b>
     * @return The default configuration that is described in {@link Default}
     */
    @Deprecated
    public static CryptographyConfiguration getDefaultConfigurationWithoutPepper() throws InvalidConfigurationException {
        return new CryptographyConfiguration();
    }
}
