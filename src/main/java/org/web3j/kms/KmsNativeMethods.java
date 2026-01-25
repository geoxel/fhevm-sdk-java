package org.web3j.kms;

import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import org.web3j.fhe.FheException;

public final class KmsNativeMethods {
    static {
        KmsNativeMethods.Init();
    }

    private static MethodHandle TKMS_public_enc_key_ml_kem512_destroy;
    private static MethodHandle TKMS_private_enc_key_ml_kem512_destroy;
    private static MethodHandle dynamic_buffer_destroy;
    private static MethodHandle TKMS_ml_kem_pke_pk_to_u8vec;
    private static MethodHandle TKMS_u8vec_to_ml_kem_pke_pk;
    private static MethodHandle TKMS_ml_kem_pke_sk_to_u8vec;
    private static MethodHandle TKMS_u8vec_to_ml_kem_pke_sk;
    private static MethodHandle TKMS_ml_kem_pke_keygen;
    private static MethodHandle TKMS_ml_kem_pke_get_pk;
    private static MethodHandle TKMS_new_server_id_addr;
    private static MethodHandle TKMS_server_id_addr_destroy;
    private static MethodHandle TKMS_new_client;
    private static MethodHandle TKMS_client_destroy;
    private static MethodHandle TKMS_process_user_decryption_resp_from_cs;
    private static MethodHandle TKMS_free_CString;

    private static void Init() {
        System.load(Paths.get("").toAbsolutePath().toString() + "/../kms/target/release/libkms_lib.dylib");

        Linker linker = Linker.nativeLinker();
        SymbolLookup lookup = SymbolLookup.loaderLookup();

        TKMS_public_enc_key_ml_kem512_destroy = linker.downcallHandle(lookup.find("TKMS_public_enc_key_ml_kem512_destroy").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
        TKMS_private_enc_key_ml_kem512_destroy = linker.downcallHandle(lookup.find("TKMS_private_enc_key_ml_kem512_destroy").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
        dynamic_buffer_destroy = linker.downcallHandle(lookup.find("destroy_dynamic_buffer").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));

        TKMS_ml_kem_pke_pk_to_u8vec = linker.downcallHandle(lookup.find("TKMS_ml_kem_pke_pk_to_u8vec").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        TKMS_u8vec_to_ml_kem_pke_pk = linker.downcallHandle(lookup.find("TKMS_u8vec_to_ml_kem_pke_pk").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        TKMS_ml_kem_pke_sk_to_u8vec = linker.downcallHandle(lookup.find("TKMS_ml_kem_pke_sk_to_u8vec").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        TKMS_u8vec_to_ml_kem_pke_sk = linker.downcallHandle(lookup.find("TKMS_u8vec_to_ml_kem_pke_sk").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        TKMS_ml_kem_pke_keygen = linker.downcallHandle(lookup.find("TKMS_ml_kem_pke_keygen").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        TKMS_ml_kem_pke_get_pk = linker.downcallHandle(lookup.find("TKMS_ml_kem_pke_get_pk").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));

        TKMS_new_server_id_addr = linker.downcallHandle(lookup.find("TKMS_new_server_id_addr").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS));
        TKMS_server_id_addr_destroy = linker.downcallHandle(lookup.find("TKMS_server_id_addr_destroy").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));

        TKMS_new_client = linker.downcallHandle(lookup.find("TKMS_new_client").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT,
                        ValueLayout.JAVA_LONG, /* void* serverAddresses */
                        ValueLayout.JAVA_INT, /* int serverAddressesLength */
                        ValueLayout.JAVA_LONG, /* String fheParameter */
                        ValueLayout.JAVA_LONG, /* String clientAddress */
                        ValueLayout.ADDRESS /* out void* client_tr */));
        TKMS_client_destroy = linker.downcallHandle(lookup.find("TKMS_client_destroy").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));

        TKMS_process_user_decryption_resp_from_cs = linker.downcallHandle(lookup.find("TKMS_process_user_decryption_resp_from_cs").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT /* return */,
                        ValueLayout.JAVA_LONG, /* void* client*/
                        ValueLayout.JAVA_LONG, /* string payloadForVerification*/
                        ValueLayout.JAVA_LONG, /* string eip712_domain_json*/
                        ValueLayout.JAVA_LONG, /* string agg_resp_json*/
                        ValueLayout.JAVA_LONG, /* void* enc_pk */
                        ValueLayout.JAVA_LONG, /* void* enc_sk */
                        ValueLayout.JAVA_LONG, /* bool verify */
                        ValueLayout.ADDRESS /* out void* cstr */));
        TKMS_free_CString = linker.downcallHandle(lookup.find("TKMS_free_CString").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.JAVA_LONG));
    }

    public static void CheckError(int error) throws FheException {
        if (error != 0)
            throw new FheException(error);
    }

    private static void CheckError(Object error) throws FheException {
        CheckError((int) error);
    }

    public record DynamicBuffer(long pointer, long length, long destructor) {
    }

    public static void DynamicBuffer_Destroy(DynamicBuffer buffer) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment inPtr = memorySegmentFromDynamicBuffer(arena);
            inPtr.set(ValueLayout.JAVA_LONG, 0, buffer.pointer());
            inPtr.set(ValueLayout.JAVA_LONG, 8, buffer.length());
            inPtr.set(ValueLayout.JAVA_LONG, 12, buffer.destructor());

            CheckError(dynamic_buffer_destroy.invoke(inPtr.address()));
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

    private static MemorySegment memorySegmentFromString(Arena arena, String value) throws Throwable {
        return arena.allocateFrom(value);
    }

    public static String memorySegmentToString(MemorySegment ms, long offset) throws Throwable {
        return ms.getString(offset, StandardCharsets.UTF_8);
    }

    public static String memorySegmentToString(MemorySegment ms) throws Throwable {
        return memorySegmentToString(ms, 0);
    }

    public static void TKMS_PublicEncKeyMlKem512_destroy(MemorySegment server_key) throws Throwable {
        CheckError(TKMS_public_enc_key_ml_kem512_destroy.invoke(server_key.address()));
    }

    public static void TKMS_PrivateEncKeyMlKem512_destroy(MemorySegment server_key) throws Throwable {
        CheckError(TKMS_private_enc_key_ml_kem512_destroy.invoke(server_key.address()));
    }

    public static DynamicBuffer TKMS_ml_kem_pke_pk_to_u8vec(MemorySegment keys) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
            CheckError(TKMS_ml_kem_pke_pk_to_u8vec.invoke(keys.address(), outPtr));
            return dynamicBufferFromMemorySegment(outPtr);
        }
    }

    public static MemorySegment TKMS_u8vec_to_ml_kem_pke_pk(byte[] data) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment datams = memorySegmentFromByteArray(arena, data);
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            CheckError(TKMS_u8vec_to_ml_kem_pke_pk.invoke(datams.address(), datams.byteSize(), outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static DynamicBuffer TKMS_ml_kem_pke_sk_to_u8vec(MemorySegment keys) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = memorySegmentFromDynamicBuffer(arena);
            CheckError(TKMS_ml_kem_pke_sk_to_u8vec.invoke(keys.address(), outPtr));
            return dynamicBufferFromMemorySegment(outPtr);
        }
    }

    public static MemorySegment TKMS_u8vec_to_ml_kem_pke_sk(byte[] data) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment datams = memorySegmentFromByteArray(arena, data);
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            CheckError(TKMS_u8vec_to_ml_kem_pke_sk.invoke(datams.address(), datams.byteSize(), outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static MemorySegment TKMS_ml_kem_pke_keygen() throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            CheckError(TKMS_ml_kem_pke_keygen.invoke(outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static MemorySegment TKMS_ml_kem_pke_get_pk(MemorySegment privateKey) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            CheckError(TKMS_ml_kem_pke_get_pk.invoke(privateKey.address(), outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static void TKMS_ServerIdAddr_destroy(MemorySegment handle) throws Throwable {
        CheckError(TKMS_server_id_addr_destroy.invoke(handle.address()));
    }

    public static MemorySegment TKMS_NewServerIdAddr(int id, String addr) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment addr_ms = memorySegmentFromString(arena, addr);
            CheckError(TKMS_new_server_id_addr.invoke(id, addr_ms.address(), outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    public static void TKMS_Client_destroy(MemorySegment handle) throws Throwable {
        CheckError(TKMS_client_destroy.invoke(handle.address()));
    }

    public static MemorySegment TKMS_NewClient(ServerIdAddr[] serverAddresses, String clientAddress, String fheParameter) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);

            MemorySegment serverAddresses_ms = arena.allocate(serverAddresses.length * ValueLayout.JAVA_LONG.byteSize());
            for (int i = 0; i < serverAddresses.length; i++) {
                serverAddresses_ms.set(ValueLayout.JAVA_LONG, i * ValueLayout.JAVA_LONG.byteSize(), serverAddresses[i].getHandle().address());
            }

            MemorySegment clientAddress_ms = memorySegmentFromString(arena, clientAddress);
            MemorySegment fheParameter_ms = memorySegmentFromString(arena, fheParameter);

            CheckError(TKMS_new_client.invoke(serverAddresses_ms.address(), serverAddresses.length, clientAddress_ms.address(),
                    fheParameter_ms.address(), outPtr));
            return outPtr.get(ValueLayout.ADDRESS, 0);
        }
    }

    private static void TKMS_free_CString(MemorySegment handle) throws Throwable {
        TKMS_free_CString.invoke(handle.address());
    }

    public static String TKMS_process_user_decryption_resp_from_cs(
            MemorySegment client,
            String payloadForVerification,
            String eip712_domain_json,
            String agg_resp_json,
            MemorySegment enc_pk,
            MemorySegment enc_sk,
            Boolean verify) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment outPtr = arena.allocate(ValueLayout.ADDRESS);

            MemorySegment payloadForVerification_ms = memorySegmentFromString(arena, payloadForVerification);
            MemorySegment eip712_domain_json_ms = memorySegmentFromString(arena, eip712_domain_json);
            MemorySegment agg_resp_json_ms = memorySegmentFromString(arena, agg_resp_json);

            CheckError(TKMS_process_user_decryption_resp_from_cs.invoke(client.address(), payloadForVerification_ms.address(),
                    eip712_domain_json_ms.address(), agg_resp_json_ms.address(), enc_pk.address(), enc_sk.address(), verify ? 1 : 0, outPtr));

            MemorySegment output_ms = outPtr.get(ValueLayout.ADDRESS, 0);

            try {
                MemorySegment scopedPtr = output_ms.reinterpret(Long.MAX_VALUE, arena, null);
                return memorySegmentToString(scopedPtr);
            }
            catch (Throwable t) {
                throw t;
            }
            finally {
                TKMS_free_CString(output_ms);
            }
        }
    }
}
