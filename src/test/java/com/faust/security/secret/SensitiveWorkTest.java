package com.faust.security.secret;

import com.faust.security.TestUtils;
import com.faust.security.exception.SecurityException;
import com.faust.security.exception.WrongPepperMethodException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SensitiveWorkTest {
    @Test
    public void DestroyAfterWork_ThrowingGeneralException_WrapsAsSecurityExceptionAndRethrows() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class, () ->
            SensitiveWork.destroyAfterWork(secrets -> {
                throw new IllegalArgumentException();
            }));
        Assertions.assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    public void DestroyAfterWork_ThrowingSecurityException_DoesntWrapButRethrows() {
        final SecurityException exception = Assertions.assertThrows(SecurityException.class, () ->
                SensitiveWork.destroyAfterWork(secrets -> {
                    throw new SecurityException("SOME EXCEPTION");
                }));
        Assertions.assertNull(exception.getCause());
    }

    @Test
    public void DestroyAfterWork_ThrowingSecurityExceptionSubclass_DoesntWrapButRethrows() {
        final WrongPepperMethodException exception = Assertions.assertThrows(WrongPepperMethodException.class, () ->
                SensitiveWork.destroyAfterWork(secrets -> {
                    throw new WrongPepperMethodException("SOME MESSAGE");
                }));
        Assertions.assertTrue(exception instanceof SecurityException); // to make sure we really are dealing with a subclass
        Assertions.assertNull(exception.getCause());
    }

    @Test
    public void DestroyAfterWork_WithSecretsAndException_DestroysSecrets() {
        final byte[] byteSecret = new byte[] { 1, 2, 3 };
        final byte[][] byteSecretsOneNull = new byte[][] { {1, 2, 3}, null, {7, 8, 9} };
        final char[] charSecret = new char[] { 1, 2, 3 };
        final char[][] charSecretsOneNull = new char[][] { null, {4, 5, 6}, {7, 8, 9} };

        Assertions.assertThrows(SecurityException.class, () ->
            SensitiveWork.destroyAfterWork(secrets -> {
                secrets.addSecret((byte[]) null);
                secrets.addSecret((char[]) null);
                secrets.addSecret((byte[][]) null);
                secrets.addSecret((char[][]) null);
                secrets.addSecret(byteSecret);
                secrets.addSecret(byteSecretsOneNull);
                secrets.addSecret(charSecret);
                secrets.addSecret(charSecretsOneNull);
                throw new Exception("SOME EXCEPTION");
            }));

        Assertions.assertTrue(TestUtils.isDestroyed(byteSecret));
        Assertions.assertTrue(TestUtils.isDestroyed(byteSecretsOneNull));
        Assertions.assertTrue(TestUtils.isDestroyed(charSecret));
        Assertions.assertTrue(TestUtils.isDestroyed(charSecretsOneNull));
    }

    @Test
    public void DestroyAfterWork_WithSecretsAndWithoutException_DestroysSecrets() throws SecurityException {
        final byte[] byteSecret = new byte[] { 1, 2, 3 };
        final byte[][] byteSecretsOneNull = new byte[][] { {1, 2, 3}, {4, 5, 6}, null };
        final char[] charSecret = new char[] { 1, 2, 3 };
        final char[][] charSecretsOneNull = new char[][] { null, {4, 5, 6}, {7, 8, 9} };

        SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret((byte[]) null);
            secrets.addSecret((char[]) null);
            secrets.addSecret((byte[][]) null);
            secrets.addSecret((char[][]) null);
            secrets.addSecret(byteSecret);
            secrets.addSecret(byteSecretsOneNull);
            secrets.addSecret(charSecret);
            secrets.addSecret(charSecretsOneNull);
            return null;
        });

        Assertions.assertTrue(TestUtils.isDestroyed(byteSecret));
        Assertions.assertTrue(TestUtils.isDestroyed(byteSecretsOneNull));
        Assertions.assertTrue(TestUtils.isDestroyed(charSecret));
        Assertions.assertTrue(TestUtils.isDestroyed(charSecretsOneNull));
    }
}
