package com.faust.security.secret;

@FunctionalInterface
public interface WorkThatCanThrow<T> {
    T work(final DestroyableSecrets destroyableSecrets) throws Throwable;
}
