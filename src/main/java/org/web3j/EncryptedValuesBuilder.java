package org.web3j;

import java.util.ArrayList;
import java.util.List;

import org.web3j.FhevmKeys.CompactPublicKeyInfo;
import org.web3j.FhevmKeys.PublicParamsInfo;
import org.web3j.fhe.CompactCiphertextListBuilder;
import org.web3j.fhe.FheValueType;
import org.web3j.fhe.ProvenCompactCiphertextList;
import org.web3j.fhe.ZkComputeLoad;
import org.web3j.tools.FheValueHelper;
import org.web3j.tools.Helpers;
import org.web3j.tools.Hex;

public final class EncryptedValuesBuilder implements AutoCloseable {
    private final CompactCiphertextListBuilder _builder;

    private int _valueCount;
    private int _bitCount;
    private List<FheValueType> _valueTypes = new ArrayList<>();

    public EncryptedValuesBuilder(CompactPublicKeyInfo compactPublicKey) throws Throwable {
        _builder = CompactCiphertextListBuilder.create(compactPublicKey.publicKey());
    }

    public void close() throws Exception {
        _builder.close();
    }

    private void checkLimit(FheValueType valueType) {
        int addedBits = FheValueHelper.getBitCount(valueType);

        if (_bitCount + addedBits > 2048)
            throw new IllegalArgumentException("Packing more than 2048 bits in a single input ciphertext is not supported");

        if (_valueCount + 1 > 256)
            throw new IllegalArgumentException("Packing more than 256 variables in a single input ciphertext is not supported");

        _bitCount += addedBits;
        ++_valueCount;
        _valueTypes.add(valueType);
    }

    List<FheValueType> getValueTypes() {
        return _valueTypes;
    }

    public EncryptedValuesBuilder pushBool(boolean value) throws Throwable {
        checkLimit(FheValueType.Bool);
        _builder.pushBool(value);
        return this;
    }

    public EncryptedValuesBuilder pushU8(byte value) throws Throwable {
        checkLimit(FheValueType.UInt8);
        _builder.pushU8(value);
        return this;
    }

    public EncryptedValuesBuilder pushU16(short value) throws Throwable {
        checkLimit(FheValueType.UInt16);
        _builder.pushU16(value);
        return this;
    }

    public EncryptedValuesBuilder pushU32(int value) throws Throwable {
        checkLimit(FheValueType.UInt32);
        _builder.pushU32(value);
        return this;
    }

    public EncryptedValuesBuilder pushU64(long value) throws Throwable {
        checkLimit(FheValueType.UInt64);
        _builder.pushU64(value);
        return this;
    }

    public byte[] encrypt(
            PublicParamsInfo publicParams,
            String aclContractAddress,
            long chainId,
            String contractAddress,
            String userAddress) throws Throwable {
        byte[] auxData = Helpers.concatArrays(
                Hex.fromHexString(Helpers.remove0xIfAny(contractAddress)),
                Hex.fromHexString(Helpers.remove0xIfAny(userAddress)),
                Hex.fromHexString(Helpers.remove0xIfAny(aclContractAddress)),
                Hex.fromHexString(String.format("%064X", chainId)));

        try (var provenCompactCiphertextList = ProvenCompactCiphertextList.buildWithProof(
                _builder,
                publicParams.publicParams(),
                auxData,
                ZkComputeLoad.Verify)) {
            return provenCompactCiphertextList.safeSerialize();
        }
    }
}
