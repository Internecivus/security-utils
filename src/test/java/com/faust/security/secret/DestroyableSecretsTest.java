package com.faust.security.secret;

import com.faust.security.TestUtils;
import com.faust.security.exception.SecurityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DestroyableSecretsTest {
    @Test
    public void DestroyableSecrets_DestroyAll_Destroys() throws SecurityException {
        final byte[] byteSecret = new byte[] { 1, 2, 3 };
        final byte[][] byteSecretsOneNull = new byte[][] { {1, 2, 3}, null, {7, 8, 9} };
        final char[] charSecret = new char[] { 1, 2, 3 };
        final char[][] charSecretsOneNull = new char[][] { null, {4, 5, 6}, {7, 8, 9} };
        final DestroyableSecrets destroyableSecrets = new DestroyableSecrets();

        destroyableSecrets.addSecret((byte[]) null);
        destroyableSecrets.addSecret((byte[][]) null);
        destroyableSecrets.addSecret((char[]) null);
        destroyableSecrets.addSecret((char[][]) null);
        destroyableSecrets.addSecret(TestUtils.getEmptyCharArray());
        destroyableSecrets.addSecret(TestUtils.getEmptyByteArray());
        destroyableSecrets.addSecret(byteSecret);
        destroyableSecrets.addSecret(byteSecretsOneNull);
        destroyableSecrets.addSecret(charSecret);
        destroyableSecrets.addSecret(charSecretsOneNull);
        destroyableSecrets.destroyAll();

        Assertions.assertTrue(TestUtils.isDestroyed(byteSecret));
        Assertions.assertTrue(TestUtils.isDestroyed(byteSecretsOneNull));
        Assertions.assertTrue(TestUtils.isDestroyed(charSecret));
        Assertions.assertTrue(TestUtils.isDestroyed(charSecretsOneNull));
    }
}
