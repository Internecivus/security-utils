package com.faust.security.utils;

import com.faust.security.exception.SecurityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class GeneratorTest {
    @Test
    public void GenerateRandomUniqueArray_BoundsSmallerThanSize_Throws() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> Generator.generateRandomUniqueArray(5, 0));
        Assertions.assertThrows(IllegalArgumentException.class, () -> Generator.generateRandomUniqueArray(7, 5));
    }

    @Test
    public void GenerateRandomUniqueArray_ValidArguments_Generates() {
        Assertions.assertEquals(6, Generator.generateRandomUniqueArray(6, 5).length);
        Assertions.assertEquals(5, Generator.generateRandomUniqueArray(5, 5).length);
        Assertions.assertEquals(4, Generator.generateRandomUniqueArray(4, 5).length);
        Assertions.assertEquals(100000, Generator.generateRandomUniqueArray(100000, 100001).length);
    }

    @Test
    public void GenerateSecureRandomUrlSafeString_PositiveSize_Generates() throws SecurityException {
        Assertions.assertEquals(13, Generator.generateSecureRandomUrlSafeCharArray(13).length);
        Assertions.assertEquals(12, Generator.generateSecureRandomUrlSafeCharArray(12).length);
        Assertions.assertEquals(11, Generator.generateSecureRandomUrlSafeCharArray(11).length);
        Assertions.assertEquals(10, Generator.generateSecureRandomUrlSafeCharArray(10).length);
        Assertions.assertEquals(9, Generator.generateSecureRandomUrlSafeCharArray(9).length);
        Assertions.assertEquals(8, Generator.generateSecureRandomUrlSafeCharArray(8).length);
        Assertions.assertEquals(7, Generator.generateSecureRandomUrlSafeCharArray(7).length);
        Assertions.assertEquals(6, Generator.generateSecureRandomUrlSafeCharArray(6).length);
        Assertions.assertEquals(3, Generator.generateSecureRandomUrlSafeCharArray(3).length);
        Assertions.assertEquals(0, Generator.generateSecureRandomUrlSafeCharArray(0).length);
    }

    @Test
    public void GenerateSecureRandomUrlSafeString_NegativeSize_Throws() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> Generator.generateSecureRandomUrlSafeCharArray(-12));
    }

    @Test
    public void GenerateSecureRandomBytes_PositiveSize_Generates() throws SecurityException {
        Assertions.assertEquals(20, Generator.generateSecureRandomBytes(20).length);
        Assertions.assertEquals(0, Generator.generateSecureRandomBytes(0).length);
    }

    @Test
    public void GenerateSecureRandomBytes_NegativeSize_Throws() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> Generator.generateSecureRandomBytes(-20));
    }
}
