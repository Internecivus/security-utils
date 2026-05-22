package com.faust.security.utils;

import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.faust.security.TestUtils;
import com.faust.security.exception.SecurityException;

public class CharUtilsTest {
    @Test
    public void CombineAndDestroy_Null_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.combineAndDestroy((char[][]) null));
    }

    @Test
    public void CombineAndDestroy_NoArrays_DoesNothing() throws SecurityException {
        final char[] emptyResult = CharUtils.combineAndDestroy();
        Assertions.assertEquals(0, emptyResult.length);
    }

    @Test
    public void CombineAndDestroy_OneArray_ReturnsSameAndDestroys() throws SecurityException {
        final String firstArray = "test1";
        final char[] oneArray = firstArray.toCharArray();
        final char[] result = CharUtils.combineAndDestroy(oneArray);
        Assertions.assertEquals(firstArray, new String(result));
        Assertions.assertTrue(TestUtils.isDestroyed(oneArray));
    }

    @Test
    public void CombineAndDestroy_FourArraysOneEmptyOneNull_CombinesAndDestroys() throws SecurityException {
        final String firstArray = "test1";
        final String secondArray = "test2";
        final String arraysCombined = firstArray + secondArray;
        final char[][] fourArraysOneEmptyOneNull = new char[][] {
                firstArray.toCharArray(), secondArray.toCharArray(), TestUtils.getEmptyCharArray(), null };

        final char[] resultCombined = CharUtils.combineAndDestroy(fourArraysOneEmptyOneNull);

        Assertions.assertEquals(arraysCombined, new String(resultCombined));
        Assertions.assertTrue(TestUtils.isDestroyed(fourArraysOneEmptyOneNull[0]));
        Assertions.assertTrue(TestUtils.isDestroyed(fourArraysOneEmptyOneNull[1]));
    }

    @Test
    public void CombineAndDestroy_TwoArrays_CombinesAndDestroys() throws SecurityException {
        final String firstArray = "test1";
        final String secondArray = "test2";
        final String arraysCombined = firstArray + secondArray;
        final char[][] twoArrays = new char[][] { firstArray.toCharArray(), secondArray.toCharArray() };

        final char[] resultCombined = CharUtils.combineAndDestroy(twoArrays);

        Assertions.assertEquals(arraysCombined, new String(resultCombined));
        Assertions.assertTrue(TestUtils.isDestroyed(twoArrays[0]));
        Assertions.assertTrue(TestUtils.isDestroyed(twoArrays[1]));
    }

    @Test
    public void GetTotalArraySize_Null_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.getTotalArraySize((char[][]) null));
    }

    @Test
    public void GetTotalArraySize_NoArrays_ZeroLength() {
        final int zeroSize = CharUtils.getTotalArraySize();
        Assertions.assertEquals(0, zeroSize);
    }

    @Test
    public void GetTotalArraySize_EmptyArrays_ZeroLength() {
        final char[] firstEmptyArray = new char[0];
        final char[] secondEmptyArray = new char[0];

        final int zeroSize = CharUtils.getTotalArraySize(firstEmptyArray, secondEmptyArray);

        Assertions.assertEquals(0, zeroSize);
    }

    @Test
    public void GetTotalArraySize_OneArray_Calculates() {
        final String firstArray = "123";
        final char[][] oneArray = new char[][] {firstArray.toCharArray() };

        final int calculatedSize = CharUtils.getTotalArraySize(oneArray);

        Assertions.assertEquals(firstArray.length(), calculatedSize);
    }

    @Test
    public void GetTotalArraySize_FourArraysOneNullAndOneEmpty_Calculates() {
        final String firstArray = "1234";
        final String secondArray = "567";
        final int totalArraySize = firstArray.length() + secondArray.length();
        final char[][] threeArrays = new char[][] {
                firstArray.toCharArray(), secondArray.toCharArray(), TestUtils.getEmptyCharArray(), null};

        final int calculatedSize = CharUtils.getTotalArraySize(threeArrays);

        Assertions.assertEquals(totalArraySize, calculatedSize);
    }

    @Test
    public void SplitAndDestroy_Null_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.splitAndDestroy(null, '-'));
    }

    @Test
    public void SplitAndDestroy_EmptyParts_DoesNothing() throws SecurityException {
        final char[][] noSplits = CharUtils.splitAndDestroy(TestUtils.getEmptyCharArray(), ':');
        Assertions.assertEquals(0, noSplits.length);
    }

    @Test
    public void SplitAndDestroy_NoParts_OneSplitAndDestroys() throws SecurityException {
        final String noPartsValue =  "123";
        final char[] noParts = noPartsValue.toCharArray();

        final char[][] noSplits = CharUtils.splitAndDestroy(noParts, ':');

        Assertions.assertEquals(1, noSplits.length);
        Assertions.assertEquals(noPartsValue, new String(noSplits[0]));
        Assertions.assertTrue(TestUtils.isDestroyed(noParts));
    }

    @Test
    public void SplitAndDestroy_TwoParts_TwoSplitsAndDestroys() throws SecurityException {
        final String delimiter = ":";
        final String firstPart = "123";
        final String secondPart = "456";
        final char[] twoParts = (firstPart + delimiter + secondPart).toCharArray();

        final char[][] twoSplits = CharUtils.splitAndDestroy(twoParts, delimiter.charAt(0));

        Assertions.assertEquals(2, twoSplits.length);
        Assertions.assertEquals(firstPart, new String(twoSplits[0]));
        Assertions.assertEquals(secondPart, new String(twoSplits[1]));
        Assertions.assertTrue(TestUtils.isDestroyed(twoParts));
    }

    @Test
    public void SplitAndDestroy_FourParts_FourSplitsAndDestroys() throws SecurityException {
        final String delimiter = ":";
        final String firstPart = "123";
        final String secondPart = "456";
        final String thirdPart = "789";
        final String fourthPart = "012";
        final char[] fourParts = (firstPart + delimiter + secondPart + delimiter + thirdPart + delimiter + fourthPart).toCharArray();

        final char[][] fourSplits = CharUtils.splitAndDestroy(fourParts, delimiter.charAt(0));

        Assertions.assertEquals(4, fourSplits.length);
        Assertions.assertEquals(firstPart, new String(fourSplits[0]));
        Assertions.assertEquals(secondPart, new String(fourSplits[1]));
        Assertions.assertEquals(thirdPart, new String(fourSplits[2]));
        Assertions.assertEquals(fourthPart, new String(fourSplits[3]));
        Assertions.assertTrue(TestUtils.isDestroyed(fourParts));
    }

    @Test
    public void Destroy_EmptyCharKey_DoesNothing() throws SecurityException {
        final char[] emptyKey = TestUtils.getEmptyCharArray();
        CharUtils.destroy(emptyKey);
    }

    @Test
    public void Destroy_EmptyByteKey_DoesNothing() throws SecurityException {
        final byte[] emptyKey = TestUtils.getEmptyByteArray();
        CharUtils.destroy(emptyKey);
    }

    @Test
    public void Destroy_NullCharKey_DoesNothing() throws SecurityException {
        final char[] key = null;
        CharUtils.destroy(key);
    }

    @Test
    public void Destroy_NullByteKey_DoesNothing() throws SecurityException {
        final byte[] key = null;
        CharUtils.destroy(key);
    }

    @Test
    public void Destroy_CharKey_Destroys() throws SecurityException {
        final char[] key = "KEY_TO_BE_DESTROYED".toCharArray();
        CharUtils.destroy(key);
        Assertions.assertTrue(TestUtils.isDestroyed(key));
    }

    @Test
    public void Destroy_ByteKey_Destroys() throws SecurityException {
        final byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        CharUtils.destroy(key);
        Assertions.assertTrue(TestUtils.isDestroyed(key));
    }

    @Test
    public void UnpaddedBase64SizeToByteSize_PositiveSize_Calculates() {
        Assertions.assertEquals(10, CharUtils.unpaddedBase64SizeToByteSize(13));
        Assertions.assertEquals(9, CharUtils.unpaddedBase64SizeToByteSize(12));
        Assertions.assertEquals(6, CharUtils.unpaddedBase64SizeToByteSize(8));
        Assertions.assertEquals(5, CharUtils.unpaddedBase64SizeToByteSize(7));
        Assertions.assertEquals(4, CharUtils.unpaddedBase64SizeToByteSize(6));
        Assertions.assertEquals(4, CharUtils.unpaddedBase64SizeToByteSize(5));
        Assertions.assertEquals(3, CharUtils.unpaddedBase64SizeToByteSize(4));
        Assertions.assertEquals(1, CharUtils.unpaddedBase64SizeToByteSize(2));
        Assertions.assertEquals(0, CharUtils.unpaddedBase64SizeToByteSize(0));
    }

    @Test
    public void UnpaddedBase64SizeToByteSize_NegativeSize_Throws() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> CharUtils.unpaddedBase64SizeToByteSize(-2));
        Assertions.assertThrows(IllegalArgumentException.class, () -> CharUtils.unpaddedBase64SizeToByteSize(-12));
    }

    @Test
    public void ByteSizeToUnpaddedBase64Size_PositiveSize_Calculates() {
        Assertions.assertEquals(18, CharUtils.byteSizeToUnpaddedBase64Size(13));
        Assertions.assertEquals(16, CharUtils.byteSizeToUnpaddedBase64Size(12));
        Assertions.assertEquals(11, CharUtils.byteSizeToUnpaddedBase64Size(8));
        Assertions.assertEquals(10, CharUtils.byteSizeToUnpaddedBase64Size(7));
        Assertions.assertEquals(8, CharUtils.byteSizeToUnpaddedBase64Size(6));
        Assertions.assertEquals(7, CharUtils.byteSizeToUnpaddedBase64Size(5));
        Assertions.assertEquals(6, CharUtils.byteSizeToUnpaddedBase64Size(4));
        Assertions.assertEquals(3, CharUtils.byteSizeToUnpaddedBase64Size(2));
        Assertions.assertEquals(0, CharUtils.byteSizeToUnpaddedBase64Size(0));
    }

    @Test
    public void ByteSizeToUnpaddedBase64Size_NegativeSize_Throws() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> CharUtils.byteSizeToUnpaddedBase64Size(-2));
        Assertions.assertThrows(IllegalArgumentException.class, () -> CharUtils.byteSizeToUnpaddedBase64Size(-12));
    }


    @Test
    public void base64EncodeAndDestroyBytesToBytes_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64EncodeAndDestroyBytesToBytes(null));
    }

    @Test
    public void base64EncodeAndDestroyBytesToChars_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64EncodeAndDestroyBytesToChars(null));
    }

    @Test
    public void base64EncodeAndDestroyCharsToBytes_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64EncodeAndDestroyCharsToBytes(null));
    }

    @Test
    public void base64EncodeAndDestroyCharsToChars_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64EncodeAndDestroyCharsToChars(null));
    }

    @Test
    public void base64DecodeAndDestroyCharsToBytes_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64DecodeAndDestroyCharsToBytes(null));
    }

    @Test
    public void base64DecodeAndDestroyCharsToChars_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64DecodeAndDestroyCharsToChars(null));
    }

    @Test
    public void base64DecodeAndDestroyBytesToBytes_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64DecodeAndDestroyBytesToBytes(null));
    }

    @Test
    public void base64DecodeAndDestroyBytesToChars_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.base64DecodeAndDestroyBytesToChars(null));
    }

    @Test
    public void base64EncodeAndDestroyBytesToBytes_EmptyValue_DoesNothing() throws SecurityException {
        final byte[] emptyBytes = CharUtils.base64EncodeAndDestroyBytesToBytes(TestUtils.getEmptyByteArray());

        Assertions.assertEquals(0, emptyBytes.length);
    }

    @Test
    public void base64EncodeAndDestroyBytesToChars_EmptyValue_DoesNothing() throws SecurityException {
        final char[] emptyChars = CharUtils.base64EncodeAndDestroyBytesToChars(TestUtils.getEmptyByteArray());

        Assertions.assertEquals(0, emptyChars.length);
    }

    @Test
    public void base64EncodeAndDestroyCharsToBytes_EmptyValue_DoesNothing() throws SecurityException {
        final byte[] emptyBytes = CharUtils.base64EncodeAndDestroyCharsToBytes(TestUtils.getEmptyCharArray());

        Assertions.assertEquals(0, emptyBytes.length);
    }

    @Test
    public void base64EncodeAndDestroyCharsToChars_EmptyValue_DoesNothing() throws SecurityException {
        final char[] emptyChars = CharUtils.base64EncodeAndDestroyCharsToChars(TestUtils.getEmptyCharArray());

        Assertions.assertEquals(0, emptyChars.length);
    }

    @Test
    public void base64DecodeAndDestroyCharsToBytes_EmptyValue_DoesNothing() throws SecurityException {
        final byte[] emptyBytes = CharUtils.base64DecodeAndDestroyCharsToBytes(TestUtils.getEmptyCharArray());

        Assertions.assertEquals(0, emptyBytes.length);
    }

    @Test
    public void base64DecodeAndDestroyCharsToChars_EmptyValue_DoesNothing() throws SecurityException {
        final char[] emptyChars = CharUtils.base64DecodeAndDestroyCharsToChars(TestUtils.getEmptyCharArray());

        Assertions.assertEquals(0, emptyChars.length);
    }

    @Test
    public void base64DecodeAndDestroyBytesToBytes_EmptyValue_DoesNothing() throws SecurityException {
        final byte[] emptyBytes = CharUtils.base64DecodeAndDestroyBytesToBytes(TestUtils.getEmptyByteArray());

        Assertions.assertEquals(0, emptyBytes.length);
    }

    @Test
    public void base64DecodeAndDestroyBytesToChars_EmptyValue_DoesNothing() throws SecurityException {
        final char[] emptyChars = CharUtils.base64DecodeAndDestroyBytesToChars(TestUtils.getEmptyByteArray());

        Assertions.assertEquals(0, emptyChars.length);
    }

    @Test
    public void base64EncodeAndDestroyBytesToBytes_NonEmptyValue_EncodesAndDestroys() throws SecurityException {
        final String decodedValue = "TEST";
        final byte[] decodedBytes = decodedValue.getBytes();
        final String expectedEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(decodedBytes);

        final byte[] encoded = CharUtils.base64EncodeAndDestroyBytesToBytes(decodedBytes);

        Assertions.assertEquals(expectedEncoded, new String(encoded));
        Assertions.assertTrue(TestUtils.isDestroyed(decodedBytes));
    }

    @Test
    public void base64EncodeAndDestroyBytesToChars_NonEmptyValue_EncodesAndDestroys() throws SecurityException {
        final String decodedValue = "TEST";
        final byte[] decodedBytes = decodedValue.getBytes();
        final String expectedEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(decodedBytes);

        final char[] encoded = CharUtils.base64EncodeAndDestroyBytesToChars(decodedBytes);

        Assertions.assertEquals(expectedEncoded, new String(encoded));
        Assertions.assertTrue(TestUtils.isDestroyed(decodedBytes));
    }

    @Test
    public void base64EncodeAndDestroyCharsToBytes_NonEmptyValue_EncodesAndDestroys() throws SecurityException {
        final String decodedValue = "TEST";
        final char[] decodedChars = decodedValue.toCharArray();
        final String expectedEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(decodedValue.getBytes());

        final byte[] encoded = CharUtils.base64EncodeAndDestroyCharsToBytes(decodedChars);

        Assertions.assertEquals(expectedEncoded, new String(encoded));
        Assertions.assertTrue(TestUtils.isDestroyed(decodedChars));
    }

    @Test
    public void base64EncodeAndDestroyCharsToChars_NonEmptyValue_EncodesAndDestroys() throws SecurityException {
        final String decodedValue = "TEST";
        final char[] decodedChars = decodedValue.toCharArray();
        final String expectedEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(decodedValue.getBytes());

        final char[] encoded = CharUtils.base64EncodeAndDestroyCharsToChars(decodedChars);

        Assertions.assertEquals(expectedEncoded, new String(encoded));
        Assertions.assertTrue(TestUtils.isDestroyed(decodedChars));
    }

    @Test
    public void base64DecodeAndDestroyCharsToBytes_NonEmptyValue_DecodesAndDestroys() throws SecurityException {
        final String expectedDecoded = "TEST";
        final String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedDecoded.getBytes());
        final char[] encodedChars = encoded.toCharArray();

        final byte[] decoded = CharUtils.base64DecodeAndDestroyCharsToBytes(encodedChars);

        Assertions.assertEquals(expectedDecoded, new String(decoded));
        Assertions.assertTrue(TestUtils.isDestroyed(encodedChars));
    }

    @Test
    public void base64DecodeAndDestroyCharsToChars_NonEmptyValue_DecodesAndDestroys() throws SecurityException {
        final String expectedDecoded = "TEST";
        final String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedDecoded.getBytes());
        final char[] encodedChars = encoded.toCharArray();

        final char[] decoded = CharUtils.base64DecodeAndDestroyCharsToChars(encodedChars);

        Assertions.assertEquals(expectedDecoded, new String(decoded));
        Assertions.assertTrue(TestUtils.isDestroyed(encodedChars));
    }

    @Test
    public void base64DecodeAndDestroyBytesToBytes_NonEmptyValue_DecodesAndDestroys() throws SecurityException {
        final String expectedDecoded = "TEST";
        final String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedDecoded.getBytes());
        final byte[] encodedBytes = encoded.getBytes();

        final byte[] decoded = CharUtils.base64DecodeAndDestroyBytesToBytes(encodedBytes);

        Assertions.assertEquals(expectedDecoded, new String(decoded));
        Assertions.assertTrue(TestUtils.isDestroyed(encodedBytes));
    }

    @Test
    public void base64DecodeAndDestroyBytesToChars_NonEmptyValue_DecodesAndDestroys() throws SecurityException {
        final String expectedDecoded = "TEST";
        final String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(expectedDecoded.getBytes());
        final byte[] encodedBytes = encoded.getBytes();

        final char[] decoded = CharUtils.base64DecodeAndDestroyBytesToChars(encodedBytes);

        Assertions.assertEquals(expectedDecoded, new String(decoded));
        Assertions.assertTrue(TestUtils.isDestroyed(encodedBytes));
    }

    @Test
    public void convertAndDestroyCharsToBytes_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.convertAndDestroyCharsToBytes(null));
    }

    @Test
    public void convertAndDestroyCharsToBytes_EmptyValue_DoesNothing() throws SecurityException {
        final byte[] emptyArray = CharUtils.convertAndDestroyCharsToBytes(TestUtils.getEmptyCharArray());

        Assertions.assertEquals(0, emptyArray.length);
    }

    @Test
    public void convertAndDestroyCharsToBytes_NonEmptyValue_ConvertsAndDestroys() throws SecurityException {
        final String valueToConvert = "TEST";
        final char[] chars = valueToConvert.toCharArray();

        final String converted = new String(CharUtils.convertAndDestroyCharsToBytes(chars));

        Assertions.assertEquals(valueToConvert, converted);
        Assertions.assertTrue(TestUtils.isDestroyed(chars));
    }

    @Test
    public void convertAndDestroyBytesToChars_NullValue_Throws() {
        Assertions.assertThrows(NullPointerException.class, () -> CharUtils.convertAndDestroyBytesToChars(null));
    }

    @Test
    public void convertAndDestroyBytesToChars_EmptyValue_DoesNothing() throws SecurityException {
        final char[] emptyArray = CharUtils.convertAndDestroyBytesToChars(TestUtils.getEmptyByteArray());

        Assertions.assertEquals(0, emptyArray.length);
    }

    @Test
    public void convertAndDestroyBytesToChars_NonEmptyValue_ConvertsAndDestroys() throws SecurityException {
        final String valueToConvert = "TEST";
        final byte[] bytes = valueToConvert.getBytes();

        final String converted = new String(CharUtils.convertAndDestroyBytesToChars(bytes));

        Assertions.assertEquals(valueToConvert, converted);
        Assertions.assertTrue(TestUtils.isDestroyed(bytes));
    }
}
