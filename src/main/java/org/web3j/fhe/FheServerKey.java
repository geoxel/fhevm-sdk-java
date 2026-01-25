package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class FheServerKey extends FheHandle {
    public FheServerKey(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.ServerKey_Destroy(handle);
    }
}
