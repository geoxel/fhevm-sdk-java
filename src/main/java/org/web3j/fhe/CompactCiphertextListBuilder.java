package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class CompactCiphertextListBuilder extends FheHandle {
    private CompactCiphertextListBuilder(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.CompactCiphertextListBuilder.Destroy(handle);
    }

    public static CompactCiphertextListBuilder create(CompactPublicKey publicKey) throws Throwable {
        MemorySegment handle = FheNativeMethods.CompactCiphertextListBuilder.Create(publicKey.getHandle());
        return new CompactCiphertextListBuilder(handle);
    }

    public void pushBool(boolean value) throws Throwable {
        FheNativeMethods.CompactCiphertextListBuilder.PushBool(getHandle(), value);
    }

    public void pushU8(byte value) throws Throwable {
        FheNativeMethods.CompactCiphertextListBuilder.PushU8(getHandle(), value);
    }

    public void pushU16(short value) throws Throwable {
        FheNativeMethods.CompactCiphertextListBuilder.PushU16(getHandle(), value);
    }

    public void pushU32(int value) throws Throwable {
        FheNativeMethods.CompactCiphertextListBuilder.PushU32(getHandle(), value);
    }

    public void pushU64(long value) throws Throwable {
        FheNativeMethods.CompactCiphertextListBuilder.PushU64(getHandle(), value);
    }
}
