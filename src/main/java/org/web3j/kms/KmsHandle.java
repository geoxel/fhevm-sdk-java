package org.web3j.kms;

import java.lang.foreign.MemorySegment;

public abstract class KmsHandle implements AutoCloseable {
    private MemorySegment _handle;

    public MemorySegment getHandle() {
        return _handle;
    }

    protected KmsHandle(MemorySegment handle) {
        _handle = handle;
    }

    public void close() {
        if (_handle != null) {
            try {
                destroyHandle(_handle);
            } catch (Throwable t) {
            }

            _handle = null;
        }
    }

    protected abstract void destroyHandle(MemorySegment handle) throws Throwable;
}
