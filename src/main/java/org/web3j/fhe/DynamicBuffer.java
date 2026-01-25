package org.web3j.fhe;

final class DynamicBuffer implements AutoCloseable {
    private FheNativeMethods.DynamicBuffer _buffer;

    public DynamicBuffer(FheNativeMethods.DynamicBuffer buffer) {
        _buffer = buffer;
    }

    public void close() {
        try {
            FheNativeMethods.DynamicBuffer_Destroy(_buffer);
        } catch (Throwable t) {
        }
    }

    public byte[] toArray() throws Throwable {
        return FheNativeMethods.DynamicBuffer_ToArray(_buffer);
    }
}
