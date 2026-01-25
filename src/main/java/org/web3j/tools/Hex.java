package org.web3j.tools;

import java.util.HexFormat;

public final class Hex {
    public static String toHexString(byte[] data) {
        return HexFormat.of().withUpperCase().formatHex(data);
    }

    public static byte[] fromHexString(String hexString) {
        return HexFormat.of().parseHex(hexString);
    }
}
