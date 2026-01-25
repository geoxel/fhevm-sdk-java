package org.web3j.tools;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import java.io.IOException;

public class ByteArrayAsNumbersSerializer extends StdSerializer<byte[]> {
    public ByteArrayAsNumbersSerializer() {
        super(byte[].class);
    }

    @Override
    public void serialize(byte[] value, JsonGenerator gen, SerializerProvider provider)
            throws IOException {
        gen.writeStartArray();
        for (byte b : value) {
            gen.writeNumber(b & 0xFF); // Convert to unsigned 0-255
        }
        gen.writeEndArray();
    }
}
