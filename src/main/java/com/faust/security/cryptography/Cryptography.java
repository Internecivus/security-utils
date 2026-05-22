package com.faust.security.cryptography;

import java.nio.ByteBuffer;
import java.text.MessageFormat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.faust.security.exception.NonMatchingConfigurationException;
import com.faust.security.exception.SecurityException;
import com.faust.security.exception.WrongPepperException;
import com.faust.security.exception.WrongPepperMethodException;
import com.faust.security.secret.SensitiveWork;
import com.faust.security.utils.CharUtils;
import com.faust.security.utils.Generator;
import lombok.NonNull;

/**
 * A class to provide easy and convenient validating and hashing of passwords.
 * Configuration is made using an instance of {@link CryptographyConfiguration}
 * that holds all of the necessary parameters.
 * <br><br>
 * Hashing is done with {@link #hashPassword} and has four steps:
 * <ul>
 *     <li>The provided password is hashed using password-based encryption (<i>PBE</i>)
 *     and a "randomly" generated salt.</li>
 *     <li>A hash-message is constructed using the following format:
 *     {ITERATIONS}{DELIMITER}{BASE64_ENCODED_SALT}{DELIMITER}{BASE64_ENCODED_HASHED_PASSWORD}
 *     and encoded with Base64.</li>
 *     <li>(optional) If a pepper is provided and the configuration supports using peppers,
 *     the hash-message is encrypted with symmetric AES encryption using a "randomly" generated IV
 *     and the pepper as the private key.</li>
 *     <li>(optional) A cipher-message is constructed using the following format:
 *     {INITIALIZATION_VECTOR}{ENCODED_HASH} and encoded with Base64.</li>
 * </ul>
 * <br><br>
 * Validation of a password against a stored hash-message is done with {@link #validatePassword}
 * and needs to use the same {@link CryptographyConfiguration} parameters as the hashing.
 * <br><br>
 * Some notes:
 * <ul>
 *     <li>The salt used is the same length as the key.</li>
 *     <li>Any exception thrown means something has gone terribly wrong and should be audited immediately.</li>
 *     <li>The resulting hash/cipher-message is a Base64 URL safe char array.</li>
 *     <li>Pepper size needs to be 256 bits (32 bytes).</li>
 *     <li>An effort has been made to clear the memory contents of sensitive data after a function
 *     is done using it. All such data is also destroyed in the event of any exception.</li>
 *     <li>You have to use the appropriate method with/without pepper depending on the used configuration.</li>
 * </ul>
 * <br><br>
 * Some recommendations:
 * <ul>
 *     <li>Choose a reasonable maximum password length (i.e. 128-256 characters) to prevent Denial-of-Service attacks.</li>
 *     <li>Choose at least 10_000 iterations, and significantly more if performance is not an issue
 *     or security is paramount.</li>
 *     <li>Choose a key length of at least 168 bits (28 bytes).</li>
 *     <li>Use {@link #fauxValidatePassword()} to prevent giving away information about credential existence.</li>
 * </ul>
 */

// TODO better encryption testing
// TODO optional base64 encoding
// TODO constant time testing (fauxValidation, wrong parameters, wrong password)
public final class Cryptography {
    // Opening these up to custom configuration would complicate things immensely, and is probably not needed in most
    // use cases.
    private final static String PEPPER_KEY_ALGORITHM = "AES";
    private final static String PEPPER_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private final static int PEPPER_SIZE_BYTES = 32;
    private final static int GCM_IV_LENGTH_BYTES = 12;
    private final static int GCM_TAG_LENGTH_BYTES = 16;

    // Do not access directly, use getters!
    private char[] _fauxPassword;
    private char[] _fauxUnpepperedHash;
    private byte[] _fauxPepper;
    private char[] _fauxPepperedHash;

    private final CryptographyConfiguration configuration;

    public Cryptography(final @NonNull CryptographyConfiguration configuration) {
        this.configuration = configuration;
        initFaux();
    }

    private byte[] getFauxPepper() {
        return _fauxPepper.clone();
    }

    private char[] getFauxPassword() {
        return _fauxPassword.clone();
    }

    private char[] getFauxUnpepperedHash() {
        return _fauxUnpepperedHash.clone();
    }

    private char[] getFauxPepperedHash() {
        return _fauxPepperedHash.clone();
    }

    private void initFaux() {
        try {
            _fauxPassword = "FAKE_PASSWORD".toCharArray();
            if (configuration.isUsePepper()) {
                _fauxPepper = Generator.generateSecureRandomBytes(PEPPER_SIZE_BYTES);
                _fauxPepperedHash = hashPassword(getFauxPassword(), getFauxPepper());
            }
            else {
                _fauxUnpepperedHash = hashPassword(getFauxPassword());
            }
        }
        catch (final SecurityException e) {
            throw new IllegalStateException("Could not initialize faux fields!", e);
        }
    }

    /**
     * Pretends to do validation to try and maintain constant time even if the result is pre-known to fail.
     * This actually does the work using pre-stored values.
     * Use when other credential parameters (such as a username or email) are invalid,
     * but you don't want to give away that fact.
     */
    public void fauxValidatePassword() throws SecurityException {
        SensitiveWork.destroyAfterWork(secrets -> {
            if (configuration.isUsePepper()) {
                validatePassword(getFauxPassword(), getFauxPepperedHash(), getFauxPepper());
            }
            else {
                validatePassword(getFauxPassword(), getFauxUnpepperedHash());
            }
            return null;
        });
    }

    /**
     * Calculate the length of the final hash, using the current configuration.
     */
    public int calculateHashLength() {
        try {
            if (configuration.isUsePepper()) {
                return hashPassword(getFauxPassword(), getFauxPepper()).length;
            }
            else {
                return hashPassword(getFauxPassword()).length;
            }
        }
        catch (final SecurityException e) {
            throw new IllegalStateException("Could not calculate hash length.", e);
        }
    }

    /**
     * Compare the provided plaintext password to the stored password hash.
     * Arguments will be destroyed after usage.
     * @param providedPassword Not null and not empty
     * @param storedHash Not null and not empty. Has to be created with the {@link #hashPassword} method
     *                   using the same {@link CryptographyConfiguration} parameters.
     * @return Password is valid
     * @throws NonMatchingConfigurationException The storedHash is constructed using
     * different {@link CryptographyConfiguration} parameters
     * @throws WrongPepperMethodException Method is used with a configuration that has peppering enabled
     * @throws IllegalArgumentException Arguments are invalid
     */
    public boolean validatePassword(final @NonNull char[] providedPassword, final @NonNull char[] storedHash)
            throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(providedPassword);
            secrets.addSecret(storedHash);

            if (configuration.isUsePepper()) {
                throw new WrongPepperMethodException("validatePassword that does not use pepper invoked using a configuration that does use pepper.");
            }
            validateHashLength(storedHash.length);
            validatePasswordLength(providedPassword.length);

            return validatePasswordAgainstHash(providedPassword, storedHash);
        });
    }

    /**
     * Compare the provided plaintext password to the stored password hash using the provided pepper.
     * Arguments will be destroyed after usage.
     * @param providedPassword Not null and not empty
     * @param storedHash Not null and not empty. Has to be created with the {@link #hashPassword} method
     *                   using the same {@link CryptographyConfiguration} parameters.
     * @param pepper 32 bytes in size
     * @return Password is valid
     * @throws NonMatchingConfigurationException The storedHash is constructed using
     * different {@link CryptographyConfiguration} parameters
     * @throws WrongPepperMethodException Method is used with a configuration that has peppering disabled
     * @throws IllegalArgumentException Arguments are invalid
     */
    public boolean validatePassword(final @NonNull char[] providedPassword, final @NonNull char[] storedHash,
            final @NonNull byte[] pepper) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(providedPassword);
            secrets.addSecret(pepper);
            secrets.addSecret(storedHash);

            if (!configuration.isUsePepper()) {
                throw new WrongPepperMethodException("validatePassword with pepper invoked using a configuration that does not use pepper.");
            }
            validateHashLength(storedHash.length);
            validatePasswordLength(providedPassword.length);
            validatePepperLength(pepper.length);

            final char[] decryptedHash = decryptWithPepper(storedHash, pepper);
            return validatePasswordAgainstHash(providedPassword, decryptedHash);
        });
    }

    private boolean validatePasswordAgainstHash(final char[] providedPassword, final char[] storedHash)
            throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            final char[] decodedStoredHash = CharUtils.base64DecodeAndDestroyCharsToChars(storedHash);

            final char[][] storedHashParts = CharUtils.splitAndDestroy(
                    decodedStoredHash, configuration.getHashPartDelimiter());
            secrets.addSecret(storedHashParts);

            if (storedHashParts.length != 3) {
                throw new NonMatchingConfigurationException(MessageFormat.format(
                        "Used hash part delimiter {0} does not match the stored hash part delimiter.",
                        configuration.getHashPartDelimiter()));
            }

            final int iterations = Integer.parseInt(String.valueOf(storedHashParts[0]));

            final byte[] salt = CharUtils.base64DecodeAndDestroyCharsToBytes(storedHashParts[1]);
            secrets.addSecret(salt);

            final byte[] storedHashedPassword = CharUtils.base64DecodeAndDestroyCharsToBytes(storedHashParts[2]);
            secrets.addSecret(storedHashedPassword);

            validateHashParameters(iterations, storedHashedPassword.length);
            final PBEKeySpec keySpec = new PBEKeySpec(providedPassword, salt, iterations,
                    storedHashedPassword.length * Byte.SIZE);

            final byte[] providedHashedPassword = SecretKeyFactory.getInstance(configuration.getHashAlgorithm())
                    .generateSecret(keySpec).getEncoded();
            secrets.addSecret(providedHashedPassword);

            keySpec.clearPassword();

            return slowEqualsAndDestroy(providedHashedPassword, storedHashedPassword);
        });
    }

    private char[] decryptWithPepper(final char[] hash, final byte[] pepper) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            final byte[] hashBytes = CharUtils.base64DecodeAndDestroyCharsToBytes(hash);
            secrets.addSecret(hashBytes);

            final ByteBuffer byteBuffer = ByteBuffer.wrap(hashBytes);
            secrets.addSecret(byteBuffer.array());

            final byte[] IV = new byte[GCM_IV_LENGTH_BYTES];
            secrets.addSecret(IV);
            byteBuffer.get(IV);

            byte[] cipherText = new byte[byteBuffer.remaining()];
            secrets.addSecret(cipherText);
            byteBuffer.get(cipherText);

            byteBuffer.clear();

            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BYTES * Byte.SIZE, IV);
            final SecretKey secretKey = new SecretKeySpec(pepper, PEPPER_KEY_ALGORITHM);
            final Cipher cipher = Cipher.getInstance(PEPPER_CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            try {
                final byte[] decryptedHash = cipher.doFinal(cipherText);

                //secretKey.destroy(); TODO Not implemented... What the fucking hell??? Need to fetch this via reflection.

                return CharUtils.convertAndDestroyBytesToChars(decryptedHash);
            }
            // TODO check exactly which exceptions are an indication a wrong key was used.
            catch (final Exception e) {
                throw new WrongPepperException(e);
            }
        });
    }

    /**
     * A slow equality method that is used to prevent certain timing attacks
     * (https://en.wikipedia.org/wiki/Timing_attack) when comparing the provided and the stored keys.
     * After the comparison, the keys are destroyed.
     * @return Keys are equal
     */
    private boolean slowEqualsAndDestroy(final byte[] keyOne, final byte[] keyOther) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(keyOne);
            secrets.addSecret(keyOther);

            int difference = keyOne.length ^ keyOther.length;
            for (int i = 0; i < keyOne.length && i < keyOther.length; i++) {
                difference |= keyOne[i] ^ keyOther[i];
            }
            return difference == 0;
        });
    }

    /**
     * Create a hash for the provided plaintext password.
     * Arguments will be destroyed after usage.
     * @param password Not null and not empty
     * @return Base64 URl safe hash
     * @throws WrongPepperMethodException Method is used with a configuration that has peppering enabled
     * @throws IllegalArgumentException Arguments are invalid
     */
    public char[] hashPassword(final @NonNull char[] password) throws SecurityException {
        return SensitiveWork.destroyAfterWork((secrets) -> {
            secrets.addSecret(password);

            if (configuration.isUsePepper()) {
                throw new WrongPepperMethodException("hashPassword that does not use pepper invoked using a configuration that does use pepper.");
            }
            validatePasswordLength(password.length);

            return createHashFromPassword(password);
        });
    }

    /**
     * Create a hash for the provided plaintext password using the provided pepper.
     * Arguments will be destroyed after usage.
     * @param password Not null and not empty
     * @param pepper 32 bytes in size
     * @return Base64 URl safe hash
     * @throws WrongPepperMethodException Method is used with a configuration that has peppering enabled
     * @throws IllegalArgumentException Arguments are invalid
     */
    public char[] hashPassword(final @NonNull char[] password, final @NonNull byte[] pepper) throws SecurityException {
        return SensitiveWork.destroyAfterWork((secrets) -> {
            secrets.addSecret(password);
            secrets.addSecret(pepper);

            if (!configuration.isUsePepper()) {
                throw new WrongPepperMethodException("validatePassword with pepper invoked using a configuration that does not use pepper.");
            }
            validatePasswordLength(password.length);
            validatePepperLength(pepper.length);

            final char[] hashedPassword = createHashFromPassword(password);
            return encryptWithPepper(hashedPassword, pepper);
        });
    }

    private char[] createHashFromPassword(final char[] password) throws SecurityException {
        return SensitiveWork.destroyAfterWork((secrets) -> {
            final byte[] salt = Generator.generateSecureRandomBytes(configuration.getKeyByteSize());
            secrets.addSecret(salt);

            final PBEKeySpec keySpec = new PBEKeySpec(password, salt, configuration.getIterations(),
                    configuration.getKeyByteSize() * Byte.SIZE);

            byte[] hashedPassword = SecretKeyFactory.getInstance(configuration.getHashAlgorithm())
                    .generateSecret(keySpec).getEncoded();
            secrets.addSecret(hashedPassword);

            keySpec.clearPassword();

            char[] hashMessage = CharUtils.combineAndDestroy(
                    String.valueOf(configuration.getIterations()).toCharArray(),
                    new char[]{configuration.getHashPartDelimiter()},
                    CharUtils.base64EncodeAndDestroyBytesToChars(salt),
                    new char[]{configuration.getHashPartDelimiter()},
                    CharUtils.base64EncodeAndDestroyBytesToChars(hashedPassword));

            return CharUtils.base64EncodeAndDestroyCharsToChars(hashMessage);
        });
    }

    // TODO Associated data
    private char[] encryptWithPepper(final char[] hash, final byte[] pepper) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            final byte[] IV = Generator.generateSecureRandomBytes(GCM_IV_LENGTH_BYTES);
            secrets.addSecret(IV);

            final GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BYTES * Byte.SIZE, IV);
            final SecretKey secretKey = new SecretKeySpec(pepper, PEPPER_KEY_ALGORITHM);
            final Cipher cipher = Cipher.getInstance(PEPPER_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

            final byte[] hashBytes = CharUtils.convertAndDestroyCharsToBytes(hash);
            secrets.addSecret(hashBytes);
            final byte[] cipherText = cipher.doFinal(hashBytes);

            //secretKey.destroy(); TODO Not implemented... What the fucking hell??? Need to fetch this via reflection.

            final ByteBuffer byteBuffer = ByteBuffer.allocate(IV.length + cipherText.length);
            secrets.addSecret(byteBuffer.array());

            byteBuffer.put(IV);
            byteBuffer.put(cipherText);

            final byte[] cipherMessage = byteBuffer.array();
            byteBuffer.clear();

            return CharUtils.base64EncodeAndDestroyBytesToChars(cipherMessage);
        });
    }

    private void validateHashParameters(final int iterations, final int keyByteSize)
            throws NonMatchingConfigurationException {
        if (iterations != configuration.getIterations()) {
            throw new NonMatchingConfigurationException(MessageFormat.format(
                    "Used configuration password iteration {0} does not match the stored configuration iteration {1}.",
                    configuration.getIterations(), iterations));
        }
        else if (keyByteSize != configuration.getKeyByteSize()) {
            throw new NonMatchingConfigurationException(MessageFormat.format(
                    "Used configuration key byte size {0} does not match the stored configuration key byte size {1}.",
                    configuration.getKeyByteSize(), keyByteSize));
        }
    }

    private void validatePasswordLength(final int passwordSize) {
        if (passwordSize == 0) {
            throw new IllegalArgumentException("Password size cannot be 0.");
        }
        else if (passwordSize > configuration.getMaximumPasswordSize()) {
            throw new IllegalArgumentException(MessageFormat.format(
                    "Password size is too long, max allowed is {0}.", configuration.getMaximumPasswordSize()));
        }
    }

    private void validateHashLength(final int hashLength) {
        if (hashLength == 0) {
            throw new IllegalArgumentException("Hash size cannot be 0.");
        }
    }

    private void validatePepperLength(final int pepperSize) {
        if (pepperSize != PEPPER_SIZE_BYTES) {
            throw new IllegalArgumentException("Pepper size needs to be " + PEPPER_SIZE_BYTES + " bytes.");
        }
    }
}
