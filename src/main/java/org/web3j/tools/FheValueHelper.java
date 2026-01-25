package org.web3j.tools;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.web3j.fhe.FheValueType;

public final class FheValueHelper {
    public static Map<FheValueType, Integer> EValueBitCount;
    static {
        Map<FheValueType, Integer> m = new HashMap<>();
        m.put(FheValueType.Bool, 2);
        m.put(FheValueType.UInt8, 8);
        m.put(FheValueType.UInt16, 16);
        m.put(FheValueType.UInt32, 32);
        m.put(FheValueType.UInt64, 64);
        m.put(FheValueType.UInt128, 128);
        m.put(FheValueType.UInt256, 256);
        m.put(FheValueType.Address, 160);
        m.put(FheValueType.Bytes64, 512);
        m.put(FheValueType.Bytes128, 1024);
        m.put(FheValueType.Bytes256, 2048);
        EValueBitCount = Collections.unmodifiableMap(m);
    }

    public static int getBitCount(FheValueType valueType) {
        Integer bits = EValueBitCount.get(valueType);
        if (bits == null)
            throw new IllegalArgumentException("Unknown FheValueType: " + valueType);
        return bits;
    }
}
