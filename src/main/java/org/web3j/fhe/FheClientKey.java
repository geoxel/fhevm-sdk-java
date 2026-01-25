package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public final class FheClientKey extends FheHandle {
    public FheClientKey(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        FheNativeMethods.ClientKey_Destroy(handle);
    }
}
