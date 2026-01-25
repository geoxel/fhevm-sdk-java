package org.web3j;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.Credentials;
import org.web3j.fhe.FheValueType;
import org.web3j.kms.Client;
import org.web3j.kms.KmsNativeMethods;
import org.web3j.kms.PrivateEncKeyMlKem512;
import org.web3j.kms.PublicEncKeyMlKem512;
import org.web3j.kms.ServerIdAddr;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.tools.AddressHelper;
import org.web3j.tools.Helpers;
import org.web3j.tools.Hex;

public final class UserDecrypt extends Decrypt {
    private final Config _config;
    private final FhevmConfig _fhevmConfig;

    private final ServerIdAddr[] _indexedKmsSigners;
    private final String _eip712Domain_json;

    /*
    private const String _aclAbi =
    @"[
        {
            'constant': true,
            'inputs': [
                { 'name': 'handle',  'type': 'bytes32' },
                { 'name': 'account', 'type': 'address' }
            ],
            'name': 'persistAllowed',
            'outputs': [ { 'name': '', 'type': 'bool' } ],
            'type': 'function'
        }
    ]";
    */

    public UserDecrypt(
            Config config,
            FhevmConfig fhevmConfig,
            List<String> kmsSigners) throws Throwable {
        _config = config;
        _fhevmConfig = fhevmConfig;

        // assume the KMS Signers have the correct order
        _indexedKmsSigners = new ServerIdAddr[kmsSigners.size()];
        for (int i = 0; i < kmsSigners.size(); i++)
            _indexedKmsSigners[i] = ServerIdAddr.create(i + 1, kmsSigners.get(i));

        // TODO: not sure, why not writing a BE uint64 at offset 24 ?
        byte[] chainIdArrayBE = new byte[32];
        ByteBuffer.wrap(chainIdArrayBE, 28, 4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(_fhevmConfig.getGatewayChainId());

        Eip712DomainMsg eip712Domain = new Eip712DomainMsg();
        eip712Domain.name = "Decryption";
        eip712Domain.version = "1";
        eip712Domain.chain_id = chainIdArrayBE;
        eip712Domain.verifying_contract = fhevmConfig.getVerifyingContractAddress();
        eip712Domain.salt = null;

        _eip712Domain_json = new ObjectMapper().writeValueAsString(eip712Domain);
    }

    public void close() {
        for (int i = 0; i < _indexedKmsSigners.length; i++)
            _indexedKmsSigners[i].close();
    }

    private static Map<String, Object> buildUserDecryptedResults(List<String> handles, List<TypedPlaintext> result) throws Throwable {
        return buildDecryptedResults(
                handles,
                result.stream().map(r -> FheValueType.fromCode(r.fhe_type)).toList(),
                result.stream().map(r -> new BigInteger(Helpers.reverseArray(r.bytes))).toList());
    }

    // https://github.com/zama-ai/fhevm-relayer/blob/96151ef300f787658c5fbaf1b4471263160032d5/src/http/userdecrypt_http_listener.rs#L20
    static final class RelayerUserDecryptPayload {
        static final class RequestValidity {
            // Seconds since the Unix Epoch (1/1/1970 00:00:00).
            public String startTimestamp;
            public String durationDays;
        };

        public HandleContractPair[] handleContractPairs;
        public RequestValidity requestValidity;
        public String contractsChainId;
        public String[] contractAddresses; // With 0x prefix.
        public String userAddress; // With 0x prefix.
        public String signature; // Without 0x prefix.
        public String publicKey; // Without 0x prefix.
        public String extraData; // With 0x prefix. Default: 0x00
    }

    static final class PayloadForVerification {
        public String signature;
        public String client_address;
        public String enc_key;
        public String[] ciphertext_handles;
        public String eip712_verifying_contract;
    }

    // Map gRPC TypedPlaintext message
    static final class TypedPlaintext {
        // The actual plaintext in bytes.
        public byte[] bytes;

        // The type of plaintext encrypted. The type should match FheType from tfhe-rs:
        // https://github.com/zama-ai/tfhe-rs/blob/main/tfhe/src/high_level_api/mod.rs
        public int fhe_type;
    }

    static final class UserDecryptionResponseHex {
        public String payload;
        public String signature;
    }

    static final class AggResp {
        public UserDecryptionResponseHex[] response;
    }

    private static void checkDeadlineValidity(LocalDateTime startTime, int durationDays) throws IllegalArgumentException {
        if (durationDays <= 0)
            throw new IllegalArgumentException("Invalid durationDays value: " + durationDays);

        final int MAX_USER_DECRYPT_DURATION_DAYS = 365;
        if (durationDays > MAX_USER_DECRYPT_DURATION_DAYS)
            throw new IllegalArgumentException(
                    "Invalid durationDays value: " + durationDays + " (max value is " + MAX_USER_DECRYPT_DURATION_DAYS + ")");

        var now = LocalDateTime.now();
        if (startTime.isAfter(now))
            throw new IllegalArgumentException("Invalid startTime: " + startTime + " (set in the future)");

        if (startTime.plusDays(durationDays).isBefore(now))
            throw new IllegalArgumentException("User decrypt request has expired");
    }

    /**
     * @param _handles
     * @param privateKey
     * @param publicKey
     * @param signature
     * @param contractAddresses
     * @param userAddress
     * @param startTime
     * @param durationDays
     * @return
     */
    @SuppressWarnings("rawtypes")
    public Map<String, Object> decrypt(
            Web3j web3j,
            List<HandleContractPair> _handles,
            String privateKey,
            String publicKey,
            String signature,
            List<String> contractAddresses,
            String userAddress,
            LocalDateTime startTime,
            int durationDays) throws Throwable {
        // Casting handles if String
        String signatureSanitized = signature != null ? Helpers.remove0xIfAny(signature) : null;
        String publicKeySanitized = Helpers.remove0xIfAny(publicKey);

        List<HandleContractPair> handles = _handles.stream()
                .map(hcp -> new HandleContractPair(Helpers.ensure0xPrefix(hcp.handle), AddressHelper.getChecksumAddress(hcp.contractAddress)))
                .collect(Collectors.toList());

        checkEncryptedBits(handles.stream().map(h -> h.handle).collect(Collectors.toList()));
        checkDeadlineValidity(startTime, durationDays);

        if (contractAddresses.size() == 0)
            throw new IllegalArgumentException("contractAddresses is empty");

        final int MAX_USER_DECRYPT_CONTRACT_ADDRESSES = 10;
        if (contractAddresses.size() > MAX_USER_DECRYPT_CONTRACT_ADDRESSES)
            throw new IllegalArgumentException("contractAddresses length exceeds " + MAX_USER_DECRYPT_CONTRACT_ADDRESSES);

        var credentials = Credentials.create(_config.EthPrivateKey);

        for (HandleContractPair hcp : handles) {
            if (userAddress == hcp.contractAddress)
                throw new IllegalArgumentException(
                        "UserAddress " + userAddress + " should not be equal to contractAddress when requesting user decryption");

            Function function;
            EthCall response;
            List<Type> output;

            function = new Function(
                    "persistAllowed",
                    Arrays.asList(
                            new Bytes32(Hex.fromHexString(Helpers.remove0xIfAny(hcp.handle))),
                            new Address(userAddress)),
                    Arrays.asList(
                            new TypeReference<org.web3j.abi.datatypes.Bool>() {
                            }));
            response = web3j.ethCall(
                    Transaction.createEthCallTransaction(credentials.getAddress(), _fhevmConfig.getAclContractAddress(),
                            FunctionEncoder.encode(function)),
                    DefaultBlockParameterName.LATEST)
                    .send();

            output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            boolean userAllowed = (boolean) output.get(0).getValue();
            if (!userAllowed)
                throw new IllegalArgumentException("User " + userAddress + " is not authorized to user decrypt handle " + hcp.handle);

            output = FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
            boolean contractAllowed = (boolean) output.get(0).getValue();
            if (!contractAllowed)
                throw new IllegalArgumentException(
                        "dapp contract " + hcp.contractAddress + " is not authorized to user decrypt handle " + hcp.handle);
        }

        /*
        TODO-SRE: ACL not implemented yet
        
        Contract contract = CounterClient.GetContract(_fhevmConfig.AclContractAddress, _aclAbi, _config, _fhevmConfig);
        Function persistAllowed_Function = contract.GetFunction("persistAllowed");
            
        foreach (HandleContractPair hcp : handles)
        {
            if (userAddress == hcp.ContractAddress)
                throw new InvalidOperationException($"UserAddress {userAddress} should not be equal to contractAddress when requesting user decryption");
            
            bool userAllowed = persistAllowed_Function.CallAsync<bool>(
                Convert.FromHexString(Helpers.Remove0xIfAny(hcp.Handle)),
                hcp.ContractAddress);
            
            if (!userAllowed)
                throw new InvalidOperationException($"User {userAddress} is not authorized to user decrypt handle {hcp.Handle}");
            
            bool contractAllowed = persistAllowed_Function.CallAsync<bool>(
                Convert.FromHexString(Helpers.Remove0xIfAny(hcp.Handle)),
                hcp.ContractAddress);
            if (!contractAllowed)
                throw new InvalidOperationException($"dapp contract {hcp.ContractAddress} is not authorized to user decrypt handle {hcp.Handle}");
        }
            */

        final String defaultExtraData = "0x00";

        var payload = new RelayerUserDecryptPayload();
        payload.handleContractPairs = handles.toArray(HandleContractPair[]::new);
        payload.requestValidity = new RelayerUserDecryptPayload.RequestValidity();
        payload.requestValidity.startTimestamp = Long.toString(Helpers.dateTimeToTimestamp(startTime));
        payload.requestValidity.durationDays = Integer.toString(durationDays);
        payload.contractsChainId = Integer.toString(_fhevmConfig.getChainId());
        payload.contractAddresses = contractAddresses.stream().map(c -> AddressHelper.getChecksumAddress(c)).toArray(String[]::new);
        payload.userAddress = AddressHelper.getChecksumAddress(userAddress);
        payload.signature = signatureSanitized != null ? signatureSanitized : "";
        payload.publicKey = publicKeySanitized;
        payload.extraData = defaultExtraData;

        String payload_json = new ObjectMapper().writeValueAsString(payload);
        String pubKeyUrl = _fhevmConfig.getRelayerUrl() + "/v1/user-decrypt";

        String agg_resp_json = Helpers.sendPostRequest(pubKeyUrl, payload_json);

        AggResp agg_resp = new ObjectMapper().readValue(agg_resp_json, AggResp.class);

        agg_resp_json = new ObjectMapper().writeValueAsString(agg_resp.response);

        var payloadForVerification = new PayloadForVerification();
        payloadForVerification.signature = signatureSanitized;
        payloadForVerification.client_address = userAddress;
        payloadForVerification.enc_key = publicKeySanitized;
        payloadForVerification.ciphertext_handles = handles.stream().map(h -> Helpers.remove0xIfAny(h.handle)).toArray(String[]::new);
        payloadForVerification.eip712_verifying_contract = _fhevmConfig.getVerifyingContractAddress();

        String payloadForVerification_json = new ObjectMapper().writeValueAsString(payloadForVerification);

        String resultJson;
        try (
                var client = Client.create(_indexedKmsSigners, userAddress, "default"/*fheParameter*/);
                var pubKey = PublicEncKeyMlKem512.deserialize(Hex.fromHexString(Helpers.remove0xIfAny(publicKey)));
                var privKey = PrivateEncKeyMlKem512.deserialize(Hex.fromHexString(Helpers.remove0xIfAny(privateKey)));) {
            resultJson = KmsNativeMethods.TKMS_process_user_decryption_resp_from_cs(
                    client.getHandle(),
                    payloadForVerification_json,
                    _eip712Domain_json,
                    agg_resp_json,
                    pubKey.getHandle(),
                    privKey.getHandle(),
                    true/*verify*/);
        }

        TypedPlaintext[] result = new ObjectMapper().readValue(resultJson, TypedPlaintext[].class);

        // Prefer building result based on the fhe_type returned by the server.
        return buildUserDecryptedResults(handles.stream().map(h -> h.handle).toList(), List.of(result));
    }
}
