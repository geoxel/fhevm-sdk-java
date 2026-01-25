package org.web3j;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.io.InvalidObjectException;
import java.math.BigInteger;

import org.web3j.fhe.FheValueType;
import org.web3j.tools.AddressHelper;
import org.web3j.tools.ByteArrayAsNumbersSerializer;
import org.web3j.tools.FheValueHelper;
import org.web3j.tools.HandleHelper;
import org.web3j.tools.Helpers;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

public abstract class Decrypt implements AutoCloseable {
    protected class Eip712DomainMsg {
        public String name;

        public String version;

        @JsonSerialize(using = ByteArrayAsNumbersSerializer.class)
        public byte[] chain_id;

        public String verifying_contract;

        @JsonSerialize(using = ByteArrayAsNumbersSerializer.class)
        public byte[] salt;
    }

    protected static void checkEncryptedBits(List<String> handles) throws IllegalArgumentException {
        int totalBits = 0;

        for (int i = 0; i < handles.size(); i++) {
            String handle = Helpers.remove0xIfAny(handles.get(i));

            if (handle.length() != 64)
                throw new IllegalArgumentException("Invalid handle length: " + handle);

            FheValueType typeDiscriminant = HandleHelper.getValueType(handle);
            Integer bitSize = FheValueHelper.EValueBitCount.get(typeDiscriminant);
            if (bitSize == null)
                throw new IllegalArgumentException("Invalid handle type: " + handle);

            totalBits += bitSize;

            // enforce 2048‑bit limit
            if (totalBits > 2048)
                throw new IllegalArgumentException("Cannot decrypt more than 2048 encrypted bits in a single request");
        }
    }

    private static Object formatAccordingToType(BigInteger value, FheValueType type) throws Throwable {
        switch (type) {
        case FheValueType.Bool:
            return value == BigInteger.ONE;
        case FheValueType.Address:
            return AddressHelper.getChecksumAddress(String.format("0x%040X", value));
        case FheValueType.Bytes64:
            return String.format("0x%0128X", value);
        case FheValueType.Bytes128:
            return String.format("0x%0256X", value);
        case FheValueType.Bytes256:
            return String.format("0x%0512X", value);
        case FheValueType.UInt8:
            return (byte) value.intValue();
        case FheValueType.UInt16:
            return (short) value.intValue();
        case FheValueType.UInt32:
            return value.intValue();
        case FheValueType.UInt64:
            return value.longValue();
        // case FheValueType.UInt128 : return (UInt128)value,
        case FheValueType.UInt256:
            return value;
        default:
            return value;
        }
    }

    protected static Map<String, Object> buildDecryptedResults(
            List<String> handles,
            List<FheValueType> types,
            List<BigInteger> values) throws Throwable {
        if (handles.size() != types.size() || handles.size() != values.size()) {
            throw new InvalidObjectException(
                    String.format(
                            "Invalid counts in results decrypting. Handles: %d, Types: %d, Bytes: %d",
                            handles.size(), types.size(), values.size()));
        }

        Map<String, Object> result = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        for (int i = 0; i < handles.size(); i++) {
            String h = handles.get(i);
            FheValueType t = types.get(i);
            BigInteger v = values.get(i);

            Object formatted = formatAccordingToType(v, t);
            result.put(h, formatted);
        }

        return result;
    }
}
