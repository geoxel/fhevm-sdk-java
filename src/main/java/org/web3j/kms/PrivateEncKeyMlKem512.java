package org.web3j.kms;

import java.lang.foreign.MemorySegment;

public final class PrivateEncKeyMlKem512 extends KmsHandle {
    public PrivateEncKeyMlKem512(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        KmsNativeMethods.TKMS_PrivateEncKeyMlKem512_destroy(handle);
    }

    public byte[] serialize() throws Throwable {
        KmsNativeMethods.DynamicBuffer buffer = KmsNativeMethods.TKMS_ml_kem_pke_sk_to_u8vec(getHandle());

        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.ToArray();
        }
    }

    public static PrivateEncKeyMlKem512 deserialize(byte[] data) throws Throwable {
        return new PrivateEncKeyMlKem512(KmsNativeMethods.TKMS_u8vec_to_ml_kem_pke_sk(data));
    }

    public static PrivateEncKeyMlKem512 generate() throws Throwable {
        MemorySegment private_key = KmsNativeMethods.TKMS_ml_kem_pke_keygen();
        return new PrivateEncKeyMlKem512(private_key);
    }
}
