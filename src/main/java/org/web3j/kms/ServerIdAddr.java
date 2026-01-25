package org.web3j.kms;

import java.lang.foreign.MemorySegment;

public final class ServerIdAddr extends KmsHandle {
    private final int _id;
    private final String _address;

    private ServerIdAddr(MemorySegment handle, int id, String addr) {
        super(handle);

        _id = id;
        _address = addr;
    }

    public int getId() {
        return _id;
    }

    public String getAddress() {
        return _address;
    }

    protected void destroyHandle(MemorySegment handle) throws Throwable {
        KmsNativeMethods.TKMS_ServerIdAddr_destroy(handle);
    }

    public static ServerIdAddr create(int id, String addr) throws Throwable {
        MemorySegment handle = KmsNativeMethods.TKMS_NewServerIdAddr(id, addr);

        return new ServerIdAddr(handle, id, addr);
    }
}
