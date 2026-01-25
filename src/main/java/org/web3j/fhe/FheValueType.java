package org.web3j.fhe;

public enum FheValueType {
    Bool(0),
    UInt8(2),
    UInt16(3),
    UInt32(4),
    UInt64(5),
    UInt128(6),
    Address(7), // a.k.a. UInt160
    UInt256(8),
    Bytes64(9),
    Bytes128(10),
    Bytes256(11);

    private final int code;

    FheValueType(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static FheValueType fromCode(int code) {
        for (FheValueType v : values())
            if (v.code == code)
                return v;
        throw new IllegalArgumentException("Unknown code: " + code);
    }
}
