package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class ProvenCompactCiphertextList extends FheHandle {
    private ProvenCompactCiphertextList(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.ProvenCompactCiphertextList.Destroy(handle);
    }

    public static ProvenCompactCiphertextList buildWithProof(
            CompactCiphertextListBuilder builder,
            CompactPkeCrs crs,
            byte[] metadata,
            ZkComputeLoad computeLoad) throws Throwable {
        MemorySegment handle = FheNativeMethods.ProvenCompactCiphertextList.BuildWithProof(
                builder.getHandle(),
                crs.getHandle(),
                metadata, computeLoad.getCode());

        return new ProvenCompactCiphertextList(handle);
    }

    public byte[] serialize() throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.ProvenCompactCiphertextList.Serialize(getHandle());

        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public static ProvenCompactCiphertextList deserialize(byte[] data) throws Throwable {
        return new ProvenCompactCiphertextList(FheNativeMethods.ProvenCompactCiphertextList.Deserialize(data));
    }

    public byte[] safeSerialize(long serialized_size_limit) throws Throwable {
        FheNativeMethods.DynamicBuffer buffer = FheNativeMethods.ProvenCompactCiphertextList.SafeSerialize(getHandle(), serialized_size_limit);
        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.toArray();
        }
    }

    public byte[] safeSerialize() throws Throwable {
        return safeSerialize(SAFE_SER_SIZE_LIMIT);
    }

    public static ProvenCompactCiphertextList safeDeserialize(byte[] data, long serialized_size_limit) throws Throwable {
        return new ProvenCompactCiphertextList(FheNativeMethods.ProvenCompactCiphertextList.SafeDeserialize(data, serialized_size_limit));
    }

    public static ProvenCompactCiphertextList safeDeserialize(byte[] data) throws Throwable {
        return safeDeserialize(data, SAFE_SER_SIZE_LIMIT);
    }
}
