package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

public abstract class FheHandle implements AutoCloseable {
    private MemorySegment _handle;

    public MemorySegment getHandle() {
        return _handle;
    }

    protected FheHandle(MemorySegment handle) {
        _handle = handle;
    }

    public void close() {
        if (_handle != null) {
            try {
                destroyHandle(_handle);
            }
            catch (Throwable t) {
            }

            _handle = null;
        }
    }

    protected abstract void destroyHandle(MemorySegment handle) throws Throwable;

    protected static final long SAFE_SER_SIZE_LIMIT = 1024L * 1024 * 1024 * 2;
}
