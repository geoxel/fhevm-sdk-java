package org.web3j;

import java.time.LocalDateTime;

import org.web3j.tools.Helpers;

public final class Eip712 {
    public static String create(
            FhevmConfig fhevmConfig,
            String publicKey,
            String[] contractAddresses,
            LocalDateTime startTime,
            int durationDays) {
        String typedDataJson = """
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
                        "UserDecryptRequestVerification": [
                            {
                                "name": "publicKey",
                                "type": "bytes"
                            },
                            {
                                "name": "contractAddresses",
                                "type": "address[]"
                            },
                            {
                                "name": "startTimestamp",
                                "type": "uint256"
                            },
                            {
                                "name": "durationDays",
                                "type": "uint256"
                            },
                            {
                                "name": "extraData",
                                "type": "bytes"
                            }
                        ]
                    },
                    "domain": {
                        "name": "Decryption",
                        "version": "1",
                        "chainId": {fhevmConfig.ChainId},
                        "verifyingContract": "{fhevmConfig.VerifyingContractAddress}"
                    },
                    "primaryType": "UserDecryptRequestVerification",
                    "message": {
                        "publicKey": "{publicKey}",
                        "contractAddresses": [{contractAddresses}],
                        "startTimestamp": "{startTimestamp}",
                        "durationDays": "{durationDays}",
                        "extraData": "0x00"
                    }
                }
                """;

        return typedDataJson
                .replace("{fhevmConfig.ChainId}", String.valueOf(fhevmConfig.getChainId()))
                .replace("{fhevmConfig.VerifyingContractAddress}", fhevmConfig.getVerifyingContractAddress())
                .replace("{contractAddresses}", "\"" + String.join("\", \"", contractAddresses) + "\"")
                .replace("{publicKey}", Helpers.ensure0xPrefix(publicKey))
                .replace("{startTimestamp}", String.valueOf(Helpers.dateTimeToTimestamp(startTime)))
                .replace("{durationDays}", String.valueOf(durationDays));
    }
}
