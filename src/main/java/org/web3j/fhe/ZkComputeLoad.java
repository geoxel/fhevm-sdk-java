package org.web3j.fhe;

public enum ZkComputeLoad {

    Proof(0),
    Verify(1);

    private final int code;

    ZkComputeLoad(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static ZkComputeLoad fromCode(int code) {
        for (ZkComputeLoad v : values())
            if (v.code == code)
                return v;
        throw new IllegalArgumentException("Unknown code: " + code);
    }
}
