package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class CompactPublicKey extends FheHandle {
    public CompactPublicKey(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.CompactPublicKey.Destroy(handle);
    }

    public byte[] serialize() throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.CompactPublicKey.Serialize(getHandle());

        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public static CompactPublicKey deserialize(byte[] data) throws Throwable {
        return new CompactPublicKey(FheNativeMethods.CompactPublicKey.Deserialize(data));
    }

    public byte[] safeSerialize(long serialized_size_limit) throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.CompactPublicKey.SafeSerialize(getHandle(), serialized_size_limit);
        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public byte[] safeSerialize() throws Throwable {
        return safeSerialize(SAFE_SER_SIZE_LIMIT);
    }

    public static CompactPublicKey safeDeserialize(byte[] data, long serialized_size_limit) throws Throwable {
        return new CompactPublicKey(FheNativeMethods.CompactPublicKey.SafeDeserialize(data, serialized_size_limit));
    }

    public static CompactPublicKey safeDeserialize(byte[] data) throws Throwable {
        return safeDeserialize(data, SAFE_SER_SIZE_LIMIT);
    }
}
