package com.faust.security.utils;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import com.faust.security.exception.SecurityException;
import com.faust.security.secret.SensitiveWork;
import lombok.NonNull;

public final class CharUtils {
    private final static Charset standardCharset = StandardCharsets.UTF_8;
    private final static Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();
    private final static Base64.Decoder base64Decoder = Base64.getUrlDecoder();

    public static char[] combineAndDestroy(final @NonNull char[] ...arrays) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(arrays);
            int totalLength = getTotalArraySize(arrays);
            int currentLength = 0;
            final char[] combined = new char[totalLength];
            for (int i = 0; i < arrays.length; i++) {
                if (arrays[i] == null) {
                    continue;
                }
                final char[] array = arrays[i];
                System.arraycopy(array, 0, combined, currentLength, array.length);
                currentLength += array.length;
            }
            return combined;
        });
    }

    public static int getTotalArraySize(final @NonNull char[] ...arrays) {
        int totalLength = 0;
        for (final char[] array : arrays) {
            if (array != null) {
                totalLength += array.length;
            }
        }
        return totalLength;
    }

    public static char[][] splitAndDestroy(final @NonNull char[] array, final char delimiter) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(array);
            if (array.length == 0) {
                return new char[0][];
            }
            final List<Integer> matchPositions = new ArrayList<>();
            for (int i = 0; i < array.length; i++) {
                final char element = array[i];
                if (element == delimiter) {
                    matchPositions.add(i);
                }
            }

            final int numberOfSplits = matchPositions.size() + 1;
            char[][] splits = new char[numberOfSplits][];
            for (int i = 0; i < numberOfSplits; i++) {
                final boolean hasPrevious = i != 0;
                final boolean isLast = i == numberOfSplits - 1;

                final int startOfSplit = hasPrevious ? matchPositions.get(i - 1) + 1 : 0;
                final int endOfSplit = !isLast ? matchPositions.get(i) : array.length;
                final int sizeOfSplit = endOfSplit - startOfSplit;

                final char[] split = new char[sizeOfSplit];
                System.arraycopy(array, startOfSplit, split, 0, sizeOfSplit);
                splits[i] = split;
            }
            return splits;
        });
    }

    public static void destroy(byte[] byteKey) throws SecurityException {
        try {
            if (byteKey == null) {
                return;
            }
            Arrays.fill(byteKey, (byte) 0);
            byteKey = null;
        }
        catch (final Throwable e) {
            throw new SecurityException(e);
        }
    }

    public static void destroy(char[] charKey) throws SecurityException {
        try {
            if (charKey == null) {
                return;
            }
            Arrays.fill(charKey, '\u0000');
            charKey = null;
        }
        catch (final Throwable e) {
            throw new SecurityException(e);
        }
    }

    public static byte[] base64EncodeAndDestroyCharsToBytes(final @NonNull char[] chars) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(chars);
            final byte[] bytes = convertAndDestroyCharsToBytes(chars);
            return base64EncodeAndDestroyBytesToBytes(bytes);
        });
    }

    public static byte[] base64EncodeAndDestroyBytesToBytes(final @NonNull byte[] bytes) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(bytes);
            return base64Encoder.encode(bytes);
        });
    }

    public static char[] base64EncodeAndDestroyCharsToChars(final @NonNull char[] chars) throws SecurityException {
        return convertAndDestroyBytesToChars(base64EncodeAndDestroyCharsToBytes(chars));
    }

    public static char[] base64EncodeAndDestroyBytesToChars(final @NonNull byte[] bytes) throws SecurityException {
        return convertAndDestroyBytesToChars(base64EncodeAndDestroyBytesToBytes(bytes));
    }

    public static byte[] base64DecodeAndDestroyCharsToBytes(final @NonNull char[] chars) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(chars);
            final byte[] bytes = convertAndDestroyCharsToBytes(chars);
            return base64DecodeAndDestroyBytesToBytes(bytes);
        });
    }

    public static byte[] base64DecodeAndDestroyBytesToBytes(final @NonNull byte[] bytes) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(bytes);
            return base64Decoder.decode(bytes);
        });
    }

    public static char[] base64DecodeAndDestroyCharsToChars(final @NonNull char[] chars) throws SecurityException {
        return convertAndDestroyBytesToChars(base64DecodeAndDestroyCharsToBytes(chars));
    }

    public static char[] base64DecodeAndDestroyBytesToChars(final @NonNull byte[] bytes) throws SecurityException {
        return convertAndDestroyBytesToChars(base64DecodeAndDestroyBytesToBytes(bytes));
    }

    public static byte[] convertAndDestroyCharsToBytes(final @NonNull char[] chars) throws SecurityException {
        return SensitiveWork.destroyAfterWork(secrets -> {
            secrets.addSecret(chars);
            final CharBuffer charBuffer = CharBuffer.wrap(chars);
            secrets.addSecret(charBuffer.array());

            final ByteBuffer byteBuffer = standardCharset.encode(charBuffer);
            secrets.addSecret(byteBuffer.array());

            byte[] bytes = Arrays.copyOf(byteBuffer.array(), byteBuffer.limit());

            charBuffer.clear();
            byteBuffer.clear();

            return bytes;
        });
    }

    public static char[] convertAndDestroyBytesToChars(final @NonNull byte[] bytes) throws SecurityException {
        return SensitiveWork.destroyAfterWork((secrets) -> {
            secrets.addSecret(bytes);
            final ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            secrets.addSecret(byteBuffer.array());

            final CharBuffer charBuffer = standardCharset.decode(byteBuffer);
            secrets.addSecret(charBuffer.array());

            final char[] chars = Arrays.copyOf(charBuffer.array(), charBuffer.limit());

            charBuffer.clear();
            byteBuffer.clear();

            return chars;
        });
    }

    public static int unpaddedBase64SizeToByteSize(final int base64Size) {
        if (base64Size < 0) {
            throw new IllegalArgumentException("Argument base64Size cannot be negative.");
        }
        return (int) Math.ceil((base64Size * 3 - 2) / 4.0);
    }

    public static int byteSizeToUnpaddedBase64Size(final int byteSize) {
        if (byteSize < 0) {
            throw new IllegalArgumentException("Argument byteSize cannot be negative.");
        }
        return (byteSize * 4 + 2) / 3;
    }
}
