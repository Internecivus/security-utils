package com.faust.security.secret;

import com.faust.security.exception.SecurityException;

public final class SensitiveWork {
    private SensitiveWork() {}

    public static <T> T destroyAfterWork(final WorkThatCanThrow<T> workThatCanThrow) throws SecurityException {
        final DestroyableSecrets destroyableSecrets = new DestroyableSecrets();
        try {
            return workThatCanThrow.work(destroyableSecrets);
        }
        catch (final Throwable e) {
            if (e instanceof SecurityException) {
                throw (SecurityException) e;
            }
            else {
                throw new SecurityException(e);
            }
        }
        finally {
            destroyableSecrets.destroyAll();
        }
    }
}
