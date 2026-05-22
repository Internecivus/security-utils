package com.faust.security.cryptography;

import com.faust.security.TestUtils;
import com.faust.security.exception.SecurityException;
import com.faust.security.exception.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Base64;

public class CryptographyTest {
    private static CryptographyConfiguration configuration1WithoutPepper;
    private static CryptographyConfiguration configuration1WithPepper;
    private static Cryptography cryptography1WithoutPepper;
    private static Cryptography cryptography1WithPepper;

    public static char[] getValidPassword1() {
        return "123$%^Test⺁دِ\uD83D\uDE02".toCharArray();
    }

    public static char[] getValidPassword2() {
        return "NOT_PASSWORD".toCharArray();
    }

    public static byte[] getValidPepper1() {
        return new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    }

    public static byte[] getValidPepperOther2() {
        return new byte[] { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    }

    public static char[] getValidHash1(){
        return "NDk5OTkvOWRERmY1N3hwT09oR2hIcVQwQnUzY183aUdyRWl4T0J5clFqQmcvS1FkMWJwZ3RHa1lwWm90b2NlMkk5VGVSTDJyQzhDMFBwRWVLNVE".toCharArray();
    }

    public static char[] getValidPepperedHash1() {
        return "1G-UkG66zyETvY5kTDa_et3iKYa18hhQlHJSVhFIh6yEC6JKxRVgXh65tX2otWUWYABLVz9RZsDQ445dJ55aFYibJjU_qmSEXTDJYmQAXx9-Ut3vHDcF9Bh4xfMYN1cOhs9P3vNZwEklGIwQaNNDvzdMa7HY9f5U64fhOUKmUoRjMoYl1wC_R7e4iA".toCharArray();
    }

    @BeforeAll
    public static void beforeAll() throws InvalidConfigurationException {
        configuration1WithoutPepper = TestUtils.getTestConfiguration1WithoutPepper();
        configuration1WithPepper = TestUtils.getTestConfiguration1WithPepper();

        cryptography1WithoutPepper = new Cryptography(configuration1WithoutPepper);
        cryptography1WithPepper = new Cryptography(configuration1WithPepper);
    }

    @Test
    public void CalculateHashLength_WithoutPepper_CorrectLength() throws SecurityException {
        final int actualLength = cryptography1WithoutPepper.hashPassword(getValidPassword1()).length;

        final int calculatedLength = cryptography1WithoutPepper.calculateHashLength();

        Assertions.assertEquals(actualLength, calculatedLength);
    }

    @Test
    public void CalculateHashLength_WithPepper_CorrectLength() throws SecurityException {
        final int actualLength = cryptography1WithPepper.hashPassword(getValidPassword1(), getValidPepper1()).length;

        final int calculatedLength = cryptography1WithPepper.calculateHashLength();

        Assertions.assertEquals(actualLength, calculatedLength);
    }

    @Test
    public void ValidatePassword_WithPepperAndNoException_ArgumentsAreDestroyed() throws SecurityException {
        final char[] hash = getValidPepperedHash1();
        final char[] password = getValidPassword1();
        final byte[] pepper = getValidPepper1();

        cryptography1WithPepper.validatePassword(password, hash, pepper);

        Assertions.assertTrue(TestUtils.isDestroyed(hash));
        Assertions.assertTrue(TestUtils.isDestroyed(pepper));
        Assertions.assertTrue(TestUtils.isDestroyed(password));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndNoException_ArgumentsAreDestroyed() throws SecurityException {
        final char[] hash = getValidHash1();
        final char[] password = getValidPassword1();

        cryptography1WithoutPepper.validatePassword(password, hash);

        Assertions.assertTrue(TestUtils.isDestroyed(hash));
        Assertions.assertTrue(TestUtils.isDestroyed(password));
    }

    @Test
    public void ValidatePassword_WithPepperAndException_ArgumentsAreDestroyed() {
        final char[] unpepperedHashThatThrows = getValidHash1();
        final char[] password = getValidPassword1();
        final byte[] pepper = getValidPepper1();

        Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(password, unpepperedHashThatThrows, pepper));
        Assertions.assertTrue(TestUtils.isDestroyed(unpepperedHashThatThrows));
        Assertions.assertTrue(TestUtils.isDestroyed(pepper));
        Assertions.assertTrue(TestUtils.isDestroyed(password));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndException_ArgumentsAreDestroyed() {
        final char[] pepperedHashThatThrows = getValidPepperedHash1();
        final char[] password = getValidPassword1();

        Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithoutPepper.validatePassword(password, pepperedHashThatThrows));
        Assertions.assertTrue(TestUtils.isDestroyed(pepperedHashThatThrows));
        Assertions.assertTrue(TestUtils.isDestroyed(password));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndDifferentHashPartDelimiter_Throws() throws SecurityException {
        final char[] hashUsingOneHashPartDelimiter = cryptography1WithoutPepper.hashPassword(getValidPassword1());
        final Cryptography cryptographyWithDifferentHashPartDelimiter = new Cryptography(new CryptographyConfiguration(
                configuration1WithoutPepper.getIterations(), configuration1WithoutPepper.getHashAlgorithm(),
                ':', configuration1WithoutPepper.getKeyByteSize(),
                configuration1WithoutPepper.getMaximumPasswordSize()));

         Assertions.assertThrows(NonMatchingConfigurationException.class,
                () -> cryptographyWithDifferentHashPartDelimiter.validatePassword(
                        getValidPassword1(), hashUsingOneHashPartDelimiter));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndDifferentIterationCount_Throws() throws SecurityException {
        final char[] hashUsingOneIterationCount = cryptography1WithoutPepper.hashPassword(getValidPassword1());
        final Cryptography cryptographyWithDifferentIterationCount = new Cryptography(new CryptographyConfiguration(
                9999, configuration1WithoutPepper.getHashAlgorithm(),
                configuration1WithoutPepper.getHashPartDelimiter(), configuration1WithoutPepper.getKeyByteSize(),
                configuration1WithoutPepper.getMaximumPasswordSize()));

        Assertions.assertThrows(NonMatchingConfigurationException.class,
                () -> cryptographyWithDifferentIterationCount.validatePassword(
                        getValidPassword1(), hashUsingOneIterationCount));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndDifferentKeySize_Throws() throws SecurityException {
        final char[] hashUsingOneKeySize = cryptography1WithoutPepper.hashPassword(getValidPassword1());
        final Cryptography cryptographyWithDifferentKeySize = new Cryptography(new CryptographyConfiguration(
                configuration1WithoutPepper.getIterations(), configuration1WithoutPepper.getHashAlgorithm(),
                configuration1WithoutPepper.getHashPartDelimiter(), 21,
                configuration1WithoutPepper.getMaximumPasswordSize()));

        Assertions.assertThrows(NonMatchingConfigurationException.class,
                () -> cryptographyWithDifferentKeySize.validatePassword(getValidPassword1(), hashUsingOneKeySize));
    }

    @Test
    public void ValidatePassword_WithPepperAndDifferentHashPartDelimiter_Throws() throws SecurityException {
        final char[] hashUsingOneHashPartDelimiter = cryptography1WithPepper.hashPassword(
                getValidPassword1(), getValidPepper1());
        final Cryptography cryptographyWithDifferentHashPartDelimiter = new Cryptography(new CryptographyConfiguration(
                configuration1WithPepper.getIterations(), configuration1WithPepper.getHashAlgorithm(),
                ':', configuration1WithPepper.getKeyByteSize(),
                configuration1WithPepper.getMaximumPasswordSize(), true));

        Assertions.assertThrows(NonMatchingConfigurationException.class,
                () -> cryptographyWithDifferentHashPartDelimiter.validatePassword(
                        getValidPassword1(), hashUsingOneHashPartDelimiter, getValidPepper1()));
    }

    @Test
    public void ValidatePassword_WithPepperAndDifferentIterationCount_Throws() throws SecurityException {
        final char[] hashUsingOneIterationCount = cryptography1WithPepper.hashPassword(getValidPassword1(), getValidPepper1());
        final Cryptography cryptographyWithDifferentIterationCount = new Cryptography(new CryptographyConfiguration(
                9999, configuration1WithPepper.getHashAlgorithm(),
                configuration1WithPepper.getHashPartDelimiter(), configuration1WithPepper.getKeyByteSize(),
                configuration1WithPepper.getMaximumPasswordSize(), true));

        Assertions.assertThrows(NonMatchingConfigurationException.class,
                () -> cryptographyWithDifferentIterationCount.validatePassword(
                        getValidPassword1(), hashUsingOneIterationCount, getValidPepper1()));
    }

    @Test
    public void ValidatePassword_WithPepperAndDifferentKeySize_Throws() throws SecurityException {
        final char[] hashUsingOneKeySize = cryptography1WithPepper.hashPassword(getValidPassword1(), getValidPepper1());
        final Cryptography cryptographyWithDifferentKeySize = new Cryptography(new CryptographyConfiguration(
                configuration1WithPepper.getIterations(), configuration1WithPepper.getHashAlgorithm(),
                configuration1WithPepper.getHashPartDelimiter(), 21,
                configuration1WithPepper.getMaximumPasswordSize(), true));

        Assertions.assertThrows(NonMatchingConfigurationException.class,
                () -> cryptographyWithDifferentKeySize.validatePassword(
                        getValidPassword1(), hashUsingOneKeySize, getValidPepper1()));
    }

    @Test
    public void FauxValidatePassword_WithPepper_DoesNotThrow() {
        Assertions.assertDoesNotThrow(() -> cryptography1WithPepper.fauxValidatePassword());
    }

    @Test
    public void FauxValidatePassword_WithoutPepper_DoesNotThrow() {
        Assertions.assertDoesNotThrow(() -> cryptography1WithoutPepper.fauxValidatePassword());
    }

    @Test
    public void ValidatePassword_WithoutPepperValidPassword_IsValid() throws SecurityException {
        final char[] hash = cryptography1WithoutPepper.hashPassword(getValidPassword1());

        final boolean isValid = cryptography1WithoutPepper.validatePassword(getValidPassword1(), hash);

        Assertions.assertTrue(isValid);
    }

    @Test
    public void ValidatePassword_WithoutPepperWrongPassword_IsNotValid() throws SecurityException {
        final char[] hash = cryptography1WithoutPepper.hashPassword(getValidPassword1());

        final boolean isValid = cryptography1WithoutPepper.validatePassword(getValidPassword2(), hash);

        Assertions.assertFalse(isValid);
    }

    @Test
    public void HashPassword_WithPepperValidPassword_IsValid() throws SecurityException {
        final char[] hash = cryptography1WithPepper.hashPassword(getValidPassword1(), getValidPepper1());

        final boolean isValid = cryptography1WithPepper.validatePassword(getValidPassword1(), hash, getValidPepper1());

        Assertions.assertTrue(isValid);
    }

    @Test
    public void HashPassword_WithPepperWrongPassword_IsNotValid() throws SecurityException {
        final char[] hash = cryptography1WithPepper.hashPassword(getValidPassword1(), getValidPepper1());

        final boolean isValid = cryptography1WithPepper.validatePassword(getValidPassword2(), hash, getValidPepper1());

        Assertions.assertFalse(isValid);
    }

    @Test
    public void HashPassword_WithPepperWrongPepper_Throws() throws SecurityException {
        final char[] hash = cryptography1WithPepper.hashPassword(getValidPassword1(), getValidPepper1());

        Assertions.assertThrows(WrongPepperException.class, () -> cryptography1WithPepper.validatePassword(getValidPassword1(), hash, getValidPepperOther2()));
    }

    @Test
    public void HashPassword_UsePepperMethodWithoutPepperConfig_Throws() {
        Assertions.assertThrows(WrongPepperMethodException.class,
                () -> cryptography1WithoutPepper.hashPassword(getValidPassword1(), getValidPepper1()));
    }

    @Test
    public void HashPassword_UsePepperlessMethodWithPepperConfig_Throws() {
        Assertions.assertThrows(WrongPepperMethodException.class,
                () -> cryptography1WithPepper.hashPassword(getValidPassword1()));
    }

    @Test
    public void ValidatePassword_UsePepperMethodWithoutPepperConfig_Throws() {
        Assertions.assertThrows(WrongPepperMethodException.class,
                () -> cryptography1WithoutPepper.validatePassword(getValidPassword1(), getValidHash1(), getValidPepper1()));
    }

    @Test
    public void ValidatePassword_UsePepperlessMethodWithPepperConfig_Throws() {
        Assertions.assertThrows(WrongPepperMethodException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), getValidHash1()));
    }

    @Test
    public void HashPassword_WithoutPepper_HashIsUrlSafe() throws SecurityException {
        final CryptographyConfiguration longKeyConfig = new CryptographyConfiguration(9999, "PBKDF2WithHmacSHA1", ' ', 1000, 64);
        final char[] hash = new Cryptography(longKeyConfig).hashPassword(getValidPassword1() );
        Assertions.assertFalse(new String(hash).contains("+"));
        Assertions.assertFalse(new String(hash).contains("/"));
    }

    @Test
    public void HashPassword_WithPepper_HashIsUrlSafe() throws SecurityException {
        final CryptographyConfiguration longKeyConfig = new CryptographyConfiguration(9999, "PBKDF2WithHmacSHA1", ' ', 1000, 64, true);
        final char[] hash = new Cryptography(longKeyConfig).hashPassword(getValidPassword1(), getValidPepper1());
        Assertions.assertFalse(new String(hash).contains("+"));
        Assertions.assertFalse(new String(hash).contains("/"));
    }

    @Test
    public void HashPassword_WithoutPepper_HashHasThreeParts() throws SecurityException {
        final char[] hash = cryptography1WithoutPepper.hashPassword(getValidPassword1() );
        final String decryptedHash = new String(Base64.getUrlDecoder().decode(new String(hash)));

        final int hashParts = decryptedHash.split(String.valueOf(configuration1WithoutPepper.getHashPartDelimiter())).length;

        Assertions.assertEquals(3, hashParts);
    }

    @Test
    public void Cryptography_NullConstructor_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> new Cryptography(null));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndNullPassword_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithoutPepper.validatePassword(null, getValidHash1()));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndEmptyPassword_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithoutPepper.validatePassword(TestUtils.getEmptyCharArray(), getValidHash1()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void ValidatePassword_WithoutPepperAndNullHash_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithoutPepper.validatePassword(getValidPassword1(), null));
    }

    @Test
    public void ValidatePassword_WithoutPepperAndEmptyHash_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithoutPepper.validatePassword(getValidPassword1(), TestUtils.getEmptyCharArray()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithoutPepperAndNullPassword_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithoutPepper.hashPassword(null));
    }

    @Test
    public void HashPassword_WithoutPepperAndEmptyPassword_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithoutPepper.hashPassword(TestUtils.getEmptyCharArray()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithoutPepperAndTooLongPassword_Throws() {
        final char[] tooLongPassword = "*".repeat(configuration1WithoutPepper.getMaximumPasswordSize() + 1).toCharArray();

        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithoutPepper.hashPassword(tooLongPassword));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void ValidatePassword_WithPepperAndNullPassword_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithoutPepper.validatePassword(null, getValidHash1(), getValidPepper1()));
    }

    @Test
    public void ValidatePassword_WithPepperAndEmptyPassword_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(
                        TestUtils.getEmptyCharArray(), getValidPepperedHash1(), getValidPepper1()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void ValidatePassword_WithPepperAndNullHash_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), null, getValidPepper1()));
    }

    @Test
    public void ValidatePassword_WithPepperAndEmptyHash_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(
                        getValidPassword1(), TestUtils.getEmptyCharArray(), getValidPepper1()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithPepperAndNullPassword_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithPepper.hashPassword(null, getValidPepper1()));
    }

    @Test
    public void HashPassword_WithPepperAndEmptyPassword_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.hashPassword(TestUtils.getEmptyCharArray(), getValidPepper1()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithPepperAndTooLongPassword_Throws() {
        final char[] tooLongPassword = "*".repeat(configuration1WithPepper.getMaximumPasswordSize() + 1).toCharArray();

        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.hashPassword(tooLongPassword, getValidPepper1()));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithPepperAndEmptyPepper_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.hashPassword(getValidPassword1(), new byte[0]));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithPepperAndNullPepper_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithPepper.hashPassword(getValidPassword1(), null));
    }

    @Test
    public void ValidatePassword_WithPepperAndNullPepper_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), getValidHash1(), null));
    }

    @Test
    public void ValidatePassword_WithPepperAndEmptyPepper_Throws() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), getValidHash1(), new byte[0]));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void HashPassword_WithPepperAndWrongSizePepper_Throws() {
        Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.hashPassword(getValidPassword1(), new byte[10]));
        Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.hashPassword(getValidPassword1(), new byte[128]));
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.hashPassword(getValidPassword1(), new byte[64]));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void ValidatePassword_WithPepperAndWrongSizePepper_Throws() {
        Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), getValidHash1(), new byte[10]));
        Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), getValidHash1(), new byte[128]));
        final SecurityException exception = Assertions.assertThrows(SecurityException.class,
                () -> cryptography1WithPepper.validatePassword(getValidPassword1(), getValidHash1(), new byte[64]));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }
}
