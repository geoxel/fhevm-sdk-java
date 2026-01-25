package org.web3j.fhe;

import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.invoke.MethodHandle;
import java.nio.file.Paths;

import org.web3j.tools.Pair;

final class FheNativeMethods {
    static {
        FheNativeMethods.Init();
    }

    private static MethodHandle config_builder_default;
    private static MethodHandle config_builder_build;
    private static MethodHandle set_server_key;
    private static MethodHandle generate_keys;
    private static MethodHandle client_key_destroy;
    private static MethodHandle server_key_destroy;
    private static MethodHandle dynamic_buffer_destroy;

    private static void Init() {
        System.load(Paths.get("").toAbsolutePath().toString() + "/../tfhe-rs/target/release/libtfhe.dylib");

        Linker linker = Linker.nativeLinker();
        SymbolLookup lookup = SymbolLookup.loaderLookup();

        config_builder_default = linker.downcallHandle(lookup.find("config_builder_default").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        config_builder_build = linker.downcallHandle(lookup.find("config_builder_build").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        set_server_key = linker.downcallHandle(lookup.find("set_server_key").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
        generate_keys = linker.downcallHandle(lookup.find("generate_keys").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
        client_key_destroy = linker.downcallHandle(lookup.find("client_key_destroy").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        server_key_destroy = linker.downcallHandle(lookup.find("server_key_destroy").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        dynamic_buffer_destroy = linker.downcallHandle(lookup.find("destroy_dynamic_buffer").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));

        // CompactPublicKey
        CompactPublicKey.destroy = linker.downcallHandle(lookup.find("compact_public_key_destroy").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        CompactPublicKey.serialize = linker.downcallHandle(lookup.find("compact_public_key_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        CompactPublicKey.deserialize = linker.downcallHandle(lookup.find("compact_public_key_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        CompactPublicKey.safeSerialize = linker.downcallHandle(lookup.find("compact_public_key_safe_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        CompactPublicKey.safeDeserialize = linker.downcallHandle(lookup.find("compact_public_key_safe_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS));

        // CompactPkeCrs
        CompactPkeCrs.destroy = linker.downcallHandle(lookup.find("compact_pke_crs_destroy").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        CompactPkeCrs.serialize = linker.downcallHandle(lookup.find("compact_pke_crs_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE, ValueLayout.ADDRESS));
        CompactPkeCrs.deserialize = linker.downcallHandle(lookup.find("compact_pke_crs_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        CompactPkeCrs.safeSerialize = linker.downcallHandle(lookup.find("compact_pke_crs_safe_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS));
        CompactPkeCrs.safeDeserialize = linker.downcallHandle(lookup.find("compact_pke_crs_safe_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS));

        // ProvenCompactCiphertextList
        ProvenCompactCiphertextList.destroy = linker.downcallHandle(lookup.find("proven_compact_ciphertext_list_destroy").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        ProvenCompactCiphertextList.buildWithProof = linker.downcallHandle(
                lookup.find("compact_ciphertext_list_builder_build_with_proof_packed").orElseThrow(),
                FunctionDescriptor.of(
                        ValueLayout.JAVA_INT /* return */,
                        ValueLayout.JAVA_LONG /* builder */,
                        ValueLayout.JAVA_LONG /* crs */,
                        ValueLayout.JAVA_LONG /* metadata */,
                        ValueLayout.JAVA_LONG /* metadata.length() */,
                        ValueLayout.JAVA_INT /* compute_load */,
                        ValueLayout.ADDRESS /* provenCompactCiphertextList* */ ));
        ProvenCompactCiphertextList.serialize = linker.downcallHandle(lookup.find("proven_compact_ciphertext_list_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        ProvenCompactCiphertextList.deserialize = linker.downcallHandle(lookup.find("proven_compact_ciphertext_list_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        ProvenCompactCiphertextList.safeSerialize = linker.downcallHandle(lookup.find("proven_compact_ciphertext_list_safe_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        ProvenCompactCiphertextList.safeDeserialize = linker.downcallHandle(
                lookup.find("proven_compact_ciphertext_list_safe_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
                        ValueLayout.ADDRESS));

        // CompactCiphertextListBuilder
        CompactCiphertextListBuilder.destroy = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_destroy").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        CompactCiphertextListBuilder.create = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_new").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        CompactCiphertextListBuilder.pushBool = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_push_bool").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE));
        CompactCiphertextListBuilder.pushU8 = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_push_u8").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_BYTE));
        CompactCiphertextListBuilder.pushU16 = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_push_u16").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_SHORT));
        CompactCiphertextListBuilder.pushU32 = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_push_u32").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT));
        CompactCiphertextListBuilder.pushU64 = linker.downcallHandle(lookup.find("compact_ciphertext_list_builder_push_u64").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG));

        // UInt8
        UInt8.encrypt = linker.downcallHandle(lookup.find("fhe_uint8_try_encrypt_with_client_key_u8").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_BYTE, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        UInt8.decrypt = linker.downcallHandle(lookup.find("fhe_uint8_decrypt").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        UInt8.destroy = linker.downcallHandle(lookup.find("fhe_uint8_destroy").orElseThrow(), FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
        UInt8.serialize = linker.downcallHandle(lookup.find("fhe_uint8_serialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        UInt8.deserialize = linker.downcallHandle(lookup.find("fhe_uint8_deserialize").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
    }

    public static void CheckError(int error) throws FheException {
        if (error != 0)
            throw new FheException(error);
    }

    private static void CheckError(Object error) throws FheException {
        CheckError((int) error);
    }

    public static MemorySegment ConfigBuilderDefault() throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            CheckError(config_builder_default.invoke(outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static MemorySegment ConfigBuilderBuild(MemorySegment config_builder) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            CheckError(config_builder_build.invoke(config_builder.address(), outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static Pair<MemorySegment, MemorySegment> GenerateKeys(MemorySegment config) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr1 = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment outPtr2 = arena.allocate(ValueLayout.ADDRESS);
            CheckError(generate_keys.invoke(config.address(), outPtr1, outPtr2));
            return new Pair<>(outPtr1.get(ValueLayout.ADDRESS, 0), outPtr2.get(ValueLayout.ADDRESS, 0));
        }
    }

    public static void SetServerKey(MemorySegment server_key) throws Throwable {
        CheckError(set_server_key.invoke(server_key.address()));
    }

    public static void ServerKey_Destroy(MemorySegment server_key) throws Throwable {
        server_key_destroy.invoke(server_key.address());
    }

    public static void ClientKey_Destroy(MemorySegment server_key) throws Throwable {
        client_key_destroy.invoke(server_key.address());
    }

    public record DynamicBuffer(long pointer, long length, long destructor) {
    }

    public static void DynamicBuffer_Destroy(DynamicBuffer buffer) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment inPtr = memorySegmentFromDynamicBuffer(arena);
            inPtr.set(ValueLayout.JAVA_LONG, 0, buffer.pointer());
            inPtr.set(ValueLayout.JAVA_LONG, 8, buffer.length());
            inPtr.set(ValueLayout.JAVA_LONG, 12, buffer.destructor());

            dynamic_buffer_destroy.invoke(inPtr.address());
        }
    }

    public static byte[] DynamicBuffer_ToArray(DynamicBuffer buffer) throws Throwable {
        final int MaxArraySize = 0x7FFFFFC7;
        if (buffer.length > MaxArraySize)
            throw new FheException(1); // TODO: use a better error code

        MemorySegment segment = MemorySegment.ofAddress(buffer.pointer).reinterpret(buffer.length);

        return segment.toArray(ValueLayout.JAVA_BYTE);
    }

    private static MemorySegment memorySegmentFromDynamicBuffer(Arena arena) throws Throwable {
        return arena.allocate(MemoryLayout.structLayout(
                ValueLayout.JAVA_LONG.withName("pointer"),
                ValueLayout.JAVA_LONG.withName("length"),
                ValueLayout.JAVA_LONG.withName("destructor")));
    }

    private static DynamicBuffer dynamicBufferFromMemorySegment(MemorySegment ms) throws Throwable {
        long pointer = ms.get(ValueLayout.JAVA_LONG, 0);
        long length = ms.get(ValueLayout.JAVA_LONG, 8);
        long destructor = ms.get(ValueLayout.JAVA_LONG, 16);

        return new DynamicBuffer(pointer, length, destructor);
    }

    private static MemorySegment memorySegmentFromByteArray(Arena arena, byte[] data) throws Throwable {
        MemorySegment ms = arena.allocate(data.length);
        MemorySegment.copy(data, 0, ms, ValueLayout.JAVA_BYTE, 0, data.length);
        return ms;
    }

    public final class CompactPublicKey {
        private static MethodHandle destroy;
        private static MethodHandle serialize;
        private static MethodHandle deserialize;
        private static MethodHandle safeSerialize;
        private static MethodHandle safeDeserialize;

        public static void Destroy(MemorySegment fhe) throws Throwable {
            destroy.invoke(fhe.address());
        }

        public static DynamicBuffer Serialize(MemorySegment fhe) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(serialize.invoke(fhe.address(), outPtr));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment Deserialize(byte[] data) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(deserialize.invoke(datams.address(), datams.byteSize(), outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }

        public static DynamicBuffer SafeSerialize(MemorySegment fhe, long serialized_size_limit) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(safeSerialize.invoke(fhe.address(), serialized_size_limit, outPtr));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment SafeDeserialize(byte[] data, long serialized_size_limit) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(safeDeserialize.invoke(datams.address(), datams.byteSize(), serialized_size_limit, outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }
    }

    public final class CompactPkeCrs {
        private static MethodHandle destroy;
        private static MethodHandle serialize;
        private static MethodHandle deserialize;
        private static MethodHandle safeSerialize;
        private static MethodHandle safeDeserialize;

        public static void Destroy(MemorySegment fhe) throws Throwable {
            destroy.invoke(fhe.address());
        }

        public static DynamicBuffer Serialize(MemorySegment fhe, boolean compress) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(serialize.invoke(fhe.address(), (byte) (compress ? 1 : 0), outPtr));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment Deserialize(byte[] data) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(deserialize.invoke(datams.address(), datams.byteSize(), outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }

        public static DynamicBuffer SafeSerialize(MemorySegment fhe, boolean compress, long serialized_size_limit) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(safeSerialize.invoke(fhe.address(), (byte) (compress ? 1 : 0), serialized_size_limit, outPtr));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment SafeDeserialize(byte[] data, long serialized_size_limit) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(safeDeserialize.invoke(datams.address(), datams.byteSize(), serialized_size_limit, outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }
    }

    public final class ProvenCompactCiphertextList {
        private static MethodHandle destroy;
        private static MethodHandle buildWithProof;
        private static MethodHandle serialize;
        private static MethodHandle deserialize;
        private static MethodHandle safeSerialize;
        private static MethodHandle safeDeserialize;

        public static void Destroy(MemorySegment fhe) throws Throwable {
            destroy.invoke(fhe.address());
        }

        public static MemorySegment BuildWithProof(
                MemorySegment builder,
                MemorySegment crs,
                byte[] metadata,
                int computeLoad) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, metadata);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(buildWithProof.invoke(builder.address(), crs.address(), datams.address(), datams.byteSize(), computeLoad, outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }

        public static DynamicBuffer Serialize(MemorySegment fhe) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(serialize.invoke(fhe.address(), outPtr));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment Deserialize(byte[] data) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(deserialize.invoke(datams.address(), datams.byteSize(), outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }

        public static DynamicBuffer SafeSerialize(MemorySegment fhe, long serialized_size_limit) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(safeSerialize.invoke(fhe.address(), outPtr, serialized_size_limit));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment SafeDeserialize(byte[] data, long serialized_size_limit) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(safeDeserialize.invoke(datams.address(), datams.byteSize(), serialized_size_limit, outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }
    }

    public final class CompactCiphertextListBuilder {
        private static MethodHandle destroy;
        private static MethodHandle create;
        private static MethodHandle pushBool;
        private static MethodHandle pushU8;
        private static MethodHandle pushU16;
        private static MethodHandle pushU32;
        private static MethodHandle pushU64;

        public static void Destroy(MemorySegment builder) throws Throwable {
            destroy.invoke(builder.address());
        }

        public static MemorySegment Create(MemorySegment publicKey) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(create.invoke(publicKey.address(), outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }

        public static void PushBool(MemorySegment builder, boolean value) throws Throwable {
            CheckError(pushBool.invoke(builder.address(), value ? 1 : 0));
        }

        public static void PushU8(MemorySegment builder, byte value) throws Throwable {
            CheckError(pushU8.invoke(builder.address(), (int) value));
        }

        public static void PushU16(MemorySegment builder, short value) throws Throwable {
            CheckError(pushU16.invoke(builder.address(), (int) value));
        }

        public static void PushU32(MemorySegment builder, int value) throws Throwable {
            CheckError(pushU32.invoke(builder.address(), value));
        }

        public static void PushU64(MemorySegment builder, long value) throws Throwable {
            CheckError(pushU64.invoke(builder.address(), value));
        }
    }

    public final class UInt8 {
        private static MethodHandle encrypt;
        private static MethodHandle decrypt;
        private static MethodHandle destroy;
        private static MethodHandle serialize;
        private static MethodHandle deserialize;

        public static MemorySegment Encrypt(byte value, MemorySegment client_key) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(encrypt.invoke(value, client_key.address(), outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }

        public static byte Decrypt(MemorySegment fhe, MemorySegment client_key) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = arena.allocate(ValueLayout.JAVA_BYTE);
                CheckError(decrypt.invoke(fhe.address(), client_key.address(), outPtr));
                return outPtr.get(ValueLayout.JAVA_BYTE, 0);
            }
        }

        public static void Destroy(MemorySegment fhe) throws Throwable {
            destroy.invoke(fhe.address());
        }

        public static DynamicBuffer Serialize(MemorySegment fhe) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
                CheckError(serialize.invoke(fhe.address(), outPtr));
                return dynamicBufferFromMemorySegment(outPtr);
            }
        }

        public static MemorySegment Deserialize(byte[] data) throws Throwable {
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment datams = memorySegmentFromByteArray(arena, data);
                MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
                CheckError(deserialize.invoke(datams.address(), datams.byteSize(), outPtr));
                return outPtr.get(ValueLayout.ADDRESS, 0);
            }
        }
    }
}
