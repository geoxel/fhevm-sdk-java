package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class CompactPkeCrs extends FheHandle {
    public CompactPkeCrs(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.CompactPkeCrs.Destroy(handle);
    }

    public byte[] serialize() throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.CompactPkeCrs.Serialize(getHandle(), false /*compress*/);

        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public static CompactPkeCrs deserialize(byte[] data) throws Throwable {
        return new CompactPkeCrs(FheNativeMethods.CompactPkeCrs.Deserialize(data));
    }

    public byte[] safeSerialize(long serialized_size_limit) throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.CompactPkeCrs.SafeSerialize(getHandle(), false /*compress*/, serialized_size_limit);
        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public byte[] safeSerialize() throws Throwable {
        return safeSerialize(SAFE_SER_SIZE_LIMIT);
    }

    public static CompactPkeCrs safeDeserialize(byte[] data, long serialized_size_limit) throws Throwable {
        return new CompactPkeCrs(FheNativeMethods.CompactPkeCrs.SafeDeserialize(data, serialized_size_limit));
    }

    public static CompactPkeCrs safeDeserialize(byte[] data) throws Throwable {
        return safeDeserialize(data, SAFE_SER_SIZE_LIMIT);
    }
}
