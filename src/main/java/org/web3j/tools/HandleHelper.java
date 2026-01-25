package org.web3j.tools;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.web3j.crypto.Hash;
import org.web3j.fhe.FheValueType;

public final class HandleHelper {
    public static FheValueType getValueType(String handle) throws IllegalArgumentException {
        String hexSubstring = handle.substring(handle.length() - 4, handle.length() - 2);
        int value = Integer.parseInt(hexSubstring, 16);
        return FheValueType.fromCode(value);
    }

    public static boolean isValid(String handle) {
        handle = Helpers.remove0xIfAny(handle);
        if (handle.length() != 64)
            return false;

        try {
            getValueType(handle);
        }
        catch (IllegalArgumentException ex) {
            return false;
        }

        return true;
    }

    private static byte[] RAW_CT_HASH_DOMAIN_SEPARATOR = "ZK-w_rct".getBytes(StandardCharsets.UTF_8);
    private static byte[] HANDLE_HASH_DOMAIN_SEPARATOR = "ZK-w_hdl".getBytes(StandardCharsets.UTF_8);

    private static byte[] keccakDigest256(byte[]... arrays) {
        return Hash.sha3(Helpers.concatArrays(arrays));
    }

    // Should be identical to:
    // https://github.com/zama-ai/fhevm-backend/blob/bae00d1b0feafb63286e94acdc58dc88dc88d9c481bf/fhevm-engine/zkproof-worker/src/verifier.rs#L301
    public static List<String> createHandles(
            List<FheValueType> fheValueTypes,
            byte[] ciphertextWithZKProof,
            String aclContractAddress,
            long chainId,
            byte ciphertextVersion) {
        byte[] blobHash = keccakDigest256(RAW_CT_HASH_DOMAIN_SEPARATOR, ciphertextWithZKProof);
        byte[] aclContractAddress20Bytes = Hex.fromHexString(Helpers.remove0xIfAny(aclContractAddress));
        byte[] chainId32Bytes = Hex.fromHexString(String.format("%064X", chainId));

        List<String> results = new ArrayList<>();
        for (int index = 0; index < fheValueTypes.size(); index++) {
            byte[] handleHash = keccakDigest256(
                    HANDLE_HASH_DOMAIN_SEPARATOR,
                    blobHash,
                    new byte[] { (byte) index },
                    aclContractAddress20Bytes,
                    chainId32Bytes);

            byte[] handleData = Helpers.concatArrays(
                    Arrays.copyOfRange(handleHash, 0, 21),
                    new byte[] { (byte) index },
                    Arrays.copyOfRange(chainId32Bytes, 24, 32),
                    new byte[] { (byte) fheValueTypes.get(index).getCode() },
                    new byte[] { ciphertextVersion });

            results.add(Helpers.to0xHexString(handleData));
        }

        return results;
    }
}
