package org.web3j.kms;

import java.lang.foreign.MemorySegment;

public final class PublicEncKeyMlKem512 extends KmsHandle {
    public PublicEncKeyMlKem512(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        KmsNativeMethods.TKMS_PublicEncKeyMlKem512_destroy(handle);
    }

    public static PublicEncKeyMlKem512 fromPrivateKey(PrivateEncKeyMlKem512 privateKey) throws Throwable {
        return new PublicEncKeyMlKem512(KmsNativeMethods.TKMS_ml_kem_pke_get_pk(privateKey.getHandle()));
    }

    public byte[] serialize() throws Throwable {
        KmsNativeMethods.DynamicBuffer buffer = KmsNativeMethods.TKMS_ml_kem_pke_pk_to_u8vec(getHandle());

        try (DynamicBuffer dynamicbuffer = new DynamicBuffer(buffer)) {
            return dynamicbuffer.ToArray();
        }
    }

    public static PublicEncKeyMlKem512 deserialize(byte[] data) throws Throwable {
        return new PublicEncKeyMlKem512(KmsNativeMethods.TKMS_u8vec_to_ml_kem_pke_pk(data));
    }

}
