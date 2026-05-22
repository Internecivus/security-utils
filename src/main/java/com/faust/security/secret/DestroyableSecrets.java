package com.faust.security.secret;

import com.faust.security.exception.SecurityException;
import com.faust.security.utils.CharUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class DestroyableSecrets {
    private final List<Object> secrets = new ArrayList<>();

    public DestroyableSecrets() {}

    public void addSecret(char[] ...charSecrets) {
        if (charSecrets != null) {
            secrets.addAll(Arrays.asList(charSecrets));
        }
    }

    public void addSecret(byte[] ...byteSecrets) {
        if (byteSecrets != null) {
            secrets.addAll(Arrays.asList(byteSecrets));
        }
    }

    public void destroyAll() throws SecurityException {
        for (final Object secret : secrets) {
            if (secret == null) {
                continue;
            }

            if (secret instanceof char[]) {
                CharUtils.destroy((char[]) secret);
            }
            else if (secret instanceof byte[]) {
                CharUtils.destroy((byte[]) secret);
            }
            else {
                throw new IllegalStateException("Asked to destroy not supported type " + secret.getClass());
            }
        }
        secrets.clear();
    }
}
