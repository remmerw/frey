package io.github.remmerw.frey;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;


/**
 * A DNS question (request).
 */
public record DnsQuestion(DnsName name, DnsRecord.TYPE type, DnsRecord.CLASS clazz,
                          boolean unicastQuery) {


    static DnsQuestion create(DnsName name, DnsRecord.TYPE type) {
        assert name != null;
        assert type != null;
        return new DnsQuestion(name, type, DnsRecord.CLASS.IN, false);
    }


    /**
     * Parse a byte array and rebuild the dns question from it.
     *
     * @param dis  The input stream.
     * @param data The plain data (for dns name references).
     * @throws IOException On errors (read outside of packet).
     */
    static DnsQuestion parse(DataInputStream dis, byte[] data) throws IOException {
        return new DnsQuestion(DnsName.parse(dis, data),
                DnsRecord.TYPE.getType(dis.readUnsignedShort()),
                DnsRecord.CLASS.getClass(dis.readUnsignedShort()), false);
    }

    /**
     * Generate a binary paket for this dns question.
     *
     * @return The dns question.
     */
    public byte[] toByteArray() {

        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutputStream dos = new DataOutputStream(baos);

        try {
            name.writeToStream(dos);
            dos.writeShort(type.getValue());
            dos.writeShort(clazz.getValue() | (unicastQuery ? (1 << 15) : 0));
            dos.flush();
        } catch (IOException e) {
            // Should never happen
            throw new RuntimeException(e);
        }
        return baos.toByteArray();

    }


}

