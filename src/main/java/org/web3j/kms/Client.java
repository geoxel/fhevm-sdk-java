package org.web3j.kms;

import java.lang.foreign.MemorySegment;

public final class Client extends KmsHandle {
    private Client(MemorySegment handle) {
        super(handle);
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        KmsNativeMethods.TKMS_Client_destroy(handle);
    }

    public static Client create(ServerIdAddr[] serverAddresses, String clientAddress, String fheParameter) throws Throwable {
        MemorySegment handle = KmsNativeMethods.TKMS_NewClient(serverAddresses, clientAddress, fheParameter);
        return new Client(handle);
    }
}
