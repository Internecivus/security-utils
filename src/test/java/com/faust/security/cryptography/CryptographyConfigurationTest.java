package com.faust.security.cryptography;

import com.faust.security.exception.InvalidConfigurationException;
import com.faust.security.exception.SecurityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CryptographyConfigurationTest {
    @Test
    public void DefaultConfiguration_DefaultValues_DoesNotThrow() {
        Assertions.assertDoesNotThrow(CryptographyConfiguration::getDefaultConfigurationWithoutPepper);
    }

    @Test
    public void DefaultConfiguration_DefaultValues_PasswordValidatesHash() throws SecurityException {
        final Cryptography cryptography = new Cryptography(CryptographyConfiguration.getDefaultConfigurationWithoutPepper());

        final char[] hash = cryptography.hashPassword(CryptographyTest.getValidPassword1());
        final boolean isValid = cryptography.validatePassword(CryptographyTest.getValidPassword1(), hash);

        Assertions.assertTrue(isValid);
    }

    @Test
    public void AllArgsConstructor_ZeroIterations_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(0, "PBKDF2WithHmacSHA1", ':', 28, 64));
    }

    @Test
    public void AllArgsConstructor_NegativeIterations_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(-5, "PBKDF2WithHmacSHA1", ':', 28, 64));
    }

    @Test
    public void AllArgsConstructor_InvalidHashAlgorithm_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(9, "NON_EXISTENT", ':', 28, 64));
    }

    @Test
    public void AllArgsConstructor_NullHashAlgorithm_Throws() {
        Assertions.assertThrows(NullPointerException.class,
                () -> new CryptographyConfiguration(9, null, ':', 28, 64));
    }

    @Test
    public void AllArgsConstructor_InvalidHashPartDelimiter_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(9, "PBKDF2WithHmacSHA1", '-', 28, 64));
    }

    @Test
    public void AllArgsConstructor_ZeroKeyByteSize_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(9, "PBKDF2WithHmacSHA1", ':', 0, 64));
    }

    @Test
    public void AllArgsConstructor_NegativeKeyByteSize_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(9, "PBKDF2WithHmacSHA1", ':', -5, 64));
    }

    @Test
    public void AllArgsConstructor_ZeroMaximumPasswordSize_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(9, "PBKDF2WithHmacSHA1", ':', 28, 0));
    }

    @Test
    public void AllArgsConstructor_NegativeMaximumPasswordSize_Throws() {
        Assertions.assertThrows(InvalidConfigurationException.class,
                () -> new CryptographyConfiguration(9, "PBKDF2WithHmacSHA1", ':', 28, -5));
    }
}
