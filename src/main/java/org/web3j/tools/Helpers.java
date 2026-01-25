package org.web3j.tools;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public final class Helpers {
    public static String remove0xIfAny(String value) {
        return StringHelper.startsWithIgnoreCase(value, "0x") ? value.substring(2) : value;
    }

    public static String ensure0xPrefix(String value) {
        return StringHelper.startsWithIgnoreCase(value, "0x") ? value : "0x" + value;
    }

    public static String to0xHexString(byte[] value) {
        return "0x" + Hex.toHexString(value).toLowerCase();
    }

    public static long dateTimeToTimestamp(LocalDateTime value) {
        return value.toEpochSecond(ZoneOffset.UTC);
    }

    public static final <T> void swapArrayElements(T[] array, int i, int j) {
        T t = array[i];
        array[i] = array[j];
        array[j] = t;
    }

    public static final void swapArrayElements(byte[] array, int i, int j) {
        byte t = array[i];
        array[i] = array[j];
        array[j] = t;
    }

    public static final byte[] reverseArray(byte[] array) {
        byte[] revArray = new byte[array.length];
        for (int i = 0; i < array.length; i++) {
            revArray[i] = array[array.length - 1 - i];
        }
        return revArray;
    }

    public static byte[] concatArrays(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        ByteBuffer byteBuffer = ByteBuffer.allocate(totalLength);
        for (byte[] array : arrays) {
            byteBuffer.put(array);
        }

        return byteBuffer.array();
    }

    public static String sendPostRequest(String url, String jsonPayload) throws IOException {
        OkHttpClient httpClient = new OkHttpClient();
        RequestBody body = RequestBody.create(
                jsonPayload,
                MediaType.parse("application/json"));

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("HTTP error: " + response.code() + " " + response.message());
            }
            return response.body().string();
        }
    }

    public static boolean IsThresholdReached(
            List<String> recoveredAddresses,
            List<String> coprocessorSigners,
            int _thresholdSigners) {
        Set<String> seen = new HashSet<>();
        for (String ra : recoveredAddresses) {
            if (!seen.add(ra)) {
                throw new IllegalArgumentException("Duplicate KMS signer address found: " + ra + " appears multiple times in recovered addresses");
            }
        }

        for (String ra : recoveredAddresses) {
            if (!coprocessorSigners.contains(ra))
                throw new IllegalArgumentException("Invalid address found: " + ra + " is not in the list of coprocessor signers");
        }

        return recoveredAddresses.size() >= _thresholdSigners;
    }
}
