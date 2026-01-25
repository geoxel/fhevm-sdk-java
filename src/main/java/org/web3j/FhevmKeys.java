package org.web3j;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.web3j.fhe.CompactPkeCrs;
import org.web3j.fhe.CompactPublicKey;

import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class FhevmKeys implements AutoCloseable {
    public record CompactPublicKeyInfo(
            CompactPublicKey publicKey,
            String publicKeyId) {
    }

    public record PublicParamsInfo(
            CompactPkeCrs publicParams,
            String publicParamsId) {
    }

    private final ConcurrentHashMap<String, Keys> _keyurlCache = new ConcurrentHashMap<>();

    public class Keys implements AutoCloseable {
        private final CompactPublicKeyInfo _compactPublicKeyInfo;
        private final PublicParamsInfo _publicParamsInfo;

        public Keys(CompactPublicKeyInfo compactPublicKeyInfo, PublicParamsInfo publicParamsInfo) {
            _compactPublicKeyInfo = compactPublicKeyInfo;
            _publicParamsInfo = publicParamsInfo;
        }

        public CompactPublicKeyInfo getCompactPublicKeyInfo() {
            return _compactPublicKeyInfo;
        }

        // 2048
        public PublicParamsInfo getPublicParamsInfo() {
            return _publicParamsInfo;
        }

        public void close() {
            _compactPublicKeyInfo.publicKey().close();
            _publicParamsInfo.publicParams().close();
        }
    }

    final static class Json {
        final static class FhePublicKey {
            public String data_id;
            public String[] urls;
        }

        final static class FheKeyInfo {
            public FhePublicKey fhe_public_key;
        }

        final static class Response {
            public FheKeyInfo[] fhe_key_info;
            public Map<String, FhePublicKey> crs;
        }

        final static class Container {
            public Response response;
        }
    }

    public void close() {
        for (Keys keys : _keyurlCache.values()) {
            keys.close();
        }
        _keyurlCache.clear();
    }

    private static byte[] httpGetBytes(OkHttpClient client, String url) throws Throwable {
        Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }
            return response.body().bytes();
        }
    }

    public Keys getOrDownload(String relayerUrl) throws Throwable {
        return getOrDownload(relayerUrl, null);
    }

    public Keys getOrDownload(String relayerUrl, String _publicKeyId) throws Throwable {
        Keys cachedKeys = _keyurlCache.get(relayerUrl);
        if (cachedKeys != null)
            return cachedKeys;

        OkHttpClient client = new OkHttpClient();

        Request request = new Request.Builder()
                .url(relayerUrl + "/v1/keyurl")
                .build();

        String json;
        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }
            json = response.body().string();
        }

        Json.Response fhevmKeys = (new ObjectMapper().readValue(json, Json.Container.class)).response;

        String pubKeyUrl;
        String publicKeyId;

        // If no publicKeyId is provided, use the first one
        // Warning: if there are multiple keys available, the first one will most likely never be the
        // same between several calls (fetching the infos is non-deterministic)
        if (_publicKeyId == null) {
            Json.FhePublicKey fhePublicKey = fhevmKeys.fhe_key_info[0].fhe_public_key;

            pubKeyUrl = fhePublicKey.urls[0];
            publicKeyId = fhePublicKey.data_id;
        } else {
            // If a publicKeyId is provided, get the corresponding info
            publicKeyId = _publicKeyId;
            Json.FheKeyInfo keyInfo = Arrays.asList(fhevmKeys.fhe_key_info).stream()
                    .filter(fki -> fki.fhe_public_key.data_id == publicKeyId)
                    .findFirst()
                    .orElse(null);
            if (keyInfo == null)
                throw new IllegalArgumentException("Could not find FHE key info with data_id " + publicKeyId);

            // TODO: Get a given party's public key url instead of the first one
            pubKeyUrl = keyInfo.fhe_public_key.urls[0];
        }

        byte[] serializedPublicKey = httpGetBytes(client, pubKeyUrl);

        String publicParamsUrl = fhevmKeys.crs.get("2048").urls[0];
        String publicParamsId = fhevmKeys.crs.get("2048").data_id;

        byte[] publicParams2048 = httpGetBytes(client, publicParamsUrl);

        CompactPublicKey publicKey = null;
        CompactPkeCrs crs = null;

        try {
            final long SERIALIZED_SIZE_LIMIT_PK = 1024 * 1024 * 512;
            publicKey = CompactPublicKey.safeDeserialize(serializedPublicKey, SERIALIZED_SIZE_LIMIT_PK);

            final long SERIALIZED_SIZE_LIMIT_CRS = 1024 * 1024 * 512;
            crs = CompactPkeCrs.safeDeserialize(publicParams2048, SERIALIZED_SIZE_LIMIT_CRS);

            Keys keys = new Keys(
                    new CompactPublicKeyInfo(publicKey, publicKeyId),
                    // 2048
                    new PublicParamsInfo(crs, publicParamsId));

            Keys existingKeys = _keyurlCache.putIfAbsent(relayerUrl, keys);
            if (existingKeys == null) {
                publicKey = null;
                crs = null;
                existingKeys = keys;
            }

            return existingKeys;
        }
        finally {
            if (crs != null)
                crs.close();
            if (publicKey != null)
                publicKey.close();
        }
    }
}
