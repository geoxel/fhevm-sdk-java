package org.web3j.fhe;

import java.lang.foreign.MemorySegment;

import org.web3j.tools.Pair;

public final class Fhe implements AutoCloseable {
    public static final Fhe Instance;

    static {
        try {
            Instance = new Fhe();
        } catch (Throwable t) {
            throw new ExceptionInInitializerError(t);
        }
    }

    private FheClientKey _clientKey;
    private FheServerKey _serverKey;

    public Fhe() throws Throwable {
        GenerateKeys();
    }

    public void close() {
        if (_clientKey != null) {
            _clientKey.close();
            _clientKey = null;
        }

        if (_serverKey != null) {
            _serverKey.close();
            _serverKey = null;
        }
    }

    public FheClientKey getClientKey() {
        return _clientKey;
    }

    public FheServerKey getServerKey() {
        return _serverKey;
    }

    private void GenerateKeys() throws Throwable {

        MemorySegment config_builder = FheNativeMethods.ConfigBuilderDefault();
        MemorySegment config = FheNativeMethods.ConfigBuilderBuild(config_builder);

        // client and server keys
        Pair<MemorySegment, MemorySegment> keys = FheNativeMethods.GenerateKeys(config);

        try {
            FheNativeMethods.SetServerKey(keys.item2());
        } catch (Throwable t) {
            FheNativeMethods.ServerKey_Destroy(keys.item2());
            FheNativeMethods.ClientKey_Destroy(keys.item1());
            throw t;
        }

        _clientKey = new FheClientKey(keys.item1());
        _serverKey = new FheServerKey(keys.item2());
    }
}
