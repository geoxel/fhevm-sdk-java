package org.web3j.kms;

final class DynamicBuffer implements AutoCloseable {
    private KmsNativeMethods.DynamicBuffer _buffer;

    public DynamicBuffer(KmsNativeMethods.DynamicBuffer buffer) {
        _buffer = buffer;
    }

    public void close() {
        try {
            KmsNativeMethods.DynamicBuffer_Destroy(_buffer);
        } catch (Throwable t) {
        }
    }

    public byte[] ToArray() throws Throwable {
        return KmsNativeMethods.DynamicBuffer_ToArray(_buffer);
    }
}
