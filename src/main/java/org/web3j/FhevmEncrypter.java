package org.web3j;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import org.web3j.FhevmKeys.PublicParamsInfo;
import org.web3j.crypto.Sign;
import org.web3j.crypto.StructuredDataEncoder;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Keys;
import org.web3j.tools.AddressHelper;
import org.web3j.tools.HandleHelper;
import org.web3j.tools.Helpers;
import org.web3j.tools.Hex;

import com.fasterxml.jackson.databind.ObjectMapper;

public final class FhevmEncrypter {
    // https://github.com/zama-ai/fhevm-relayer/blob/96151ef300f787658c5fbaf1b4471263160032d5/src/http/input_http_listener.rs#L17
    static final class FhevmInputProofPayload {
        // Hex encoded uint256 string without prefix
        public String contractChainId;
        // Hex encoded address with 0x prefix.
        public String contractAddress;
        // Hex encoded address with 0x prefix.
        public String userAddress;
        // List of hex encoded binary proof without 0x prefix
        public String ciphertextWithInputVerification;
        // Hex encoded bytes with 0x prefix. Default: 0x00
        public String extraData;
    }

    static final class Json {
        static final class Response {
            public String[] handles;
            public String[] signatures;
        }

        static final class Container {
            public Response response;
        }
    }

    public static FhevmEncryptedValues Encrypt(
            FhevmConfig fhevmConfig,
            EncryptedValuesBuilder builder,
            PublicParamsInfo publicParams,
            List<String> coprocessorSigners,
            int coprocessorSignersThreshold,
            String contractAddress,
            String userAddress) throws Throwable {
        if (!AddressHelper.isAddress(contractAddress))
            throw new IllegalArgumentException("Invalid contract address");

        if (!AddressHelper.isAddress(userAddress))
            throw new IllegalArgumentException("Invalid user address");

        final String defaultExtraData = "0x00";
        byte[] ciphertext = builder.encrypt(
                publicParams,
                fhevmConfig.getAclContractAddress(),
                fhevmConfig.getChainId(),
                contractAddress,
                userAddress);

        FhevmInputProofPayload payload = new FhevmInputProofPayload();
        payload.contractChainId = "0x" + String.format("%X", fhevmConfig.getChainId()).toLowerCase();
        payload.contractAddress = AddressHelper.getChecksumAddress(contractAddress);
        payload.userAddress = AddressHelper.getChecksumAddress(userAddress);
        payload.ciphertextWithInputVerification = Hex.toHexString(ciphertext);
        payload.extraData = defaultExtraData;

        String payload_json = new ObjectMapper().writeValueAsString(payload);
        String pubKeyUrl = fhevmConfig.getRelayerUrl() + "/v1/input-proof";

        String json = Helpers.sendPostRequest(pubKeyUrl, payload_json);

        Json.Response resp = (new ObjectMapper().readValue(json, Json.Container.class)).response;

        List<String> handles = HandleHelper.createHandles(
                builder.getValueTypes(),
                ciphertext,
                fhevmConfig.getAclContractAddress(),
                fhevmConfig.getChainId(),
                (byte) 0 /* ciphertextVersion */);

        if (handles.size() != resp.handles.length)
            throw new IllegalArgumentException(
                    String.format("Incorrect Handles list sizes: (expected: %d) != (received: %d)", handles.size(), resp.handles.length));

        for (int i = 0; i < handles.size(); i++) {
            String h = handles.get(i);
            String rh = resp.handles[i];
            if (!h.equals(rh))
                throw new IllegalArgumentException(String.format("Incorrect handle: (expected: %s) != (received: %s)", h, rh));
        }

        String typedDataJsonTemplate = """
                {
                    "types": {
                        "EIP712Domain": [
                            {
                                "name": "name",
                                "type": "string"
                            },
                            {
                                "name": "version",
                                "type": "string"
                            },
                            {
                                "name": "chainId",
                                "type": "uint256"
                            },
                            {
                                "name": "verifyingContract",
                                "type": "address"
                            }
                        ],
                        "CiphertextVerification": [
                            {
                                "name": "ctHandles",
                                "type": "bytes32[]"
                            },
                            {
                                "name": "userAddress",
                                "type": "address"
                            },
                            {
                                "name": "contractAddress",
                                "type": "address"
                            },
                            {
                                "name": "contractChainId",
                                "type": "uint256"
                            },
                            {
                                "name": "extraData",
                                "type": "bytes"
                            }
                        ]
                    },
                    "domain": {
                        "name": "InputVerification",
                        "version": "1",
                        "chainId": {fhevmConfig.GatewayChainId},
                        "verifyingContract": "{fhevmConfig.VerifyingContractAddressInputVerification}"
                    },
                    "primaryType": "CiphertextVerification",
                    "message": {
                        "ctHandles": [{ctHandles}],
                        "userAddress": "{userAddress}",
                        "contractAddress": "{contractAddress}",
                        "contractChainId": {fhevmConfig.ChainId},
                        "extraData": "0x00"
                    }
                }
                """;

        String typedDataJson = typedDataJsonTemplate
                .replace("{fhevmConfig.GatewayChainId}", String.valueOf(fhevmConfig.getGatewayChainId()))
                .replace("{fhevmConfig.VerifyingContractAddressInputVerification}", fhevmConfig.getVerifyingContractAddressInputVerification())
                .replace("{ctHandles}", "\"" + String.join("\", \"", handles.stream().map(h -> h.substring(2)).toList()) + "\"")
                .replace("{userAddress}", userAddress)
                .replace("{contractAddress}", contractAddress)
                .replace("{fhevmConfig.ChainId}", Integer.toString(fhevmConfig.getChainId()));

        List<String> recoveredAddresses = Arrays.asList(resp.signatures)
                .stream()
                .map(signature -> {
                    try {
                        return recoverFromTypedData(typedDataJson, Helpers.remove0xIfAny(signature), fhevmConfig.getChainId());
                    }
                    catch (Exception e) {
                        throw new RuntimeException("Failed to recover signature", e);
                    }
                })
                .toList();

        if (!Helpers.IsThresholdReached(recoveredAddresses, coprocessorSigners, coprocessorSignersThreshold))
            throw new IllegalStateException("Coprocessor signers threshold is not reached");

        // inputProof is len(list_handles) + numCoprocessorSigners + list_handles + signatureCoprocessorSigners (1+1+NUM_HANDLES*32+65*numSigners)
        String inputProof = String.join(
                "",
                String.format("%02X", handles.size()),
                String.format("%02X", resp.signatures.length),
                String.join("", handles.stream().map(s -> s.substring(2)).toList()),
                String.join("", Arrays.asList(resp.signatures).stream().map(s -> s.substring(2)).toList()),
                defaultExtraData.substring(2));
                
        return new FhevmEncryptedValues(handles, inputProof);
    }

    // typedDataJson: EIP-712 structured data JSON string
    // signature: 0x-prefixed 65-byte signature hex string
    private static String recoverFromTypedData(String typedDataJson, String signatureHex, long chainId) throws Exception {
        byte[] signatureBytes = Hex.fromHexString(signatureHex); // TODO-SRE Numeric.hexStringToByteArray(signatureHex);

        // Extract v, r, s from signature
        byte v = signatureBytes[64];
        if (v < 27)
            v += 27;

        byte[] r = Arrays.copyOfRange(signatureBytes, 0, 32);
        byte[] s = Arrays.copyOfRange(signatureBytes, 32, 64);

        Sign.SignatureData signData = new Sign.SignatureData(v, r, s);
        int recId = Sign.getRecId(signData, chainId);

        StructuredDataEncoder dataEncoder = new StructuredDataEncoder(typedDataJson);
        byte[] typedDataHash = dataEncoder.hashStructuredData();

        // Try all recovery IDs (0-3)
        BigInteger pubKey = Sign.recoverFromSignature(
                (byte) recId,
                new ECDSASignature(
                        new BigInteger(1, signData.getR()),
                        new BigInteger(1, signData.getS())),
                typedDataHash);

        if (pubKey == null) {
            return null;
        }
        return AddressHelper.getChecksumAddress(Keys.getAddress(pubKey));
    }
}
