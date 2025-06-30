package io.github.remmerw.frey;

import android.util.SparseArray;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;

/**
 * A generic DNS record.
 */
public record DnsRecord(DnsName name, TYPE type, CLASS clazz, int clazzValue, long ttl,
                        DnsData payloadDnsData) {

    public static DnsRecord create(DnsName name, TYPE type, int clazzValue, long ttl, DnsData payloadDnsData) {
        return new DnsRecord(name, type, CLASS.NONE, clazzValue, ttl, payloadDnsData);
    }

    /**
     * Parse a given record based on the full message data and the current
     * stream position.
     *
     * @param dis  The DataInputStream positioned at the first record byte.
     * @param data The full message data.
     * @return the record which was parsed.
     * @throws IOException In case of malformed replies.
     */
    public static DnsRecord parse(DataInputStream dis, byte[] data) throws IOException {
        DnsName name = DnsName.parse(dis, data);
        int typeValue = dis.readUnsignedShort();
        TYPE type = TYPE.getType(typeValue);
        int clazzValue = dis.readUnsignedShort();
        CLASS clazz = CLASS.getClass(clazzValue & 0x7fff);
        long ttl = (((long) dis.readUnsignedShort()) << 16) +
                dis.readUnsignedShort();
        int payloadLength = dis.readUnsignedShort();
        DnsData payloadDnsData = switch (type) {
            case TXT -> DnsData.TXT.parse(dis, payloadLength);
            case OPT -> DnsData.OPT.parse(dis, payloadLength);
            default -> DnsData.UNKNOWN.parse(dis, payloadLength);
        };
        return new DnsRecord(name, type, clazz, clazzValue, ttl, payloadDnsData);
    }

    private void toOutputStream(OutputStream outputStream) throws IOException {
        if (payloadDnsData == null) {
            throw new IllegalStateException("Empty Record has no byte representation");
        }

        DataOutputStream dos = new DataOutputStream(outputStream);

        name.writeToStream(dos);
        dos.writeShort(type.getValue());
        dos.writeShort(clazzValue);
        dos.writeInt((int) ttl);

        dos.writeShort(payloadDnsData.length());
        payloadDnsData.toOutputStream(dos);
    }

    public byte[] toByteArray() {
        int totalSize = name.size()
                + 10 // 2 byte short type + 2 byte short classValue + 4 byte int ttl + 2 byte short payload length.
                + payloadDnsData.length();
        ByteArrayOutputStream baos = new ByteArrayOutputStream(totalSize);
        DataOutputStream dos = new DataOutputStream(baos);
        try {
            toOutputStream(dos);
        } catch (IOException e) {
            // Should never happen.
            throw new AssertionError(e);
        }
        return baos.toByteArray();
    }

    /**
     * Retrieve a textual representation of this resource record.
     *
     * @return String
     */

    @Override
    public String toString() {
        return name.getRawAce() + ".\t" + ttl + '\t' + clazz + '\t' + type + '\t' + payloadDnsData;
    }

    /**
     * Check if this record answers a given query.
     *
     * @param q The query.
     * @return True if this record is a valid answer.
     */
    public boolean isAnswer(DnsQuestion q) {
        return ((q.type() == type) || (q.type() == TYPE.ANY)) &&
                ((q.clazz() == clazz) || (q.clazz() == CLASS.ANY)) &&
                q.name().equals(name);
    }

    /**
     * The payload data, usually a subclass of data (A, AAAA, CNAME, ...).
     *
     * @return The payload data.
     */
    public DnsData getPayload() {
        return payloadDnsData;
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof DnsRecord otherDnsRecord)) {
            return false;
        }
        if (other == this) {
            return true;
        }
        if (!name.equals(otherDnsRecord.name)) return false;
        if (type != otherDnsRecord.type) return false;
        if (clazz != otherDnsRecord.clazz) return false;
        // Note that we do not compare the TTL here, since we consider two Records with everything but the TTL equal to
        // be equal too.
        return payloadDnsData.equals(otherDnsRecord.payloadDnsData);
    }


    /**
     * The resource record type.
     *
     * @see <a href=
     * "http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4">
     * IANA DNS Parameters - Resource Record (RR) TYPEs</a>
     */
    public enum TYPE {
        UNKNOWN(-1),
        A(1),
        TXT(16),
        OPT(41),
        ANY(255),
        AAAA(28),
        ;

        /**
         * Internal lookup table to map values to types.
         */
        private static final SparseArray<TYPE> INVERSE_LUT = new SparseArray<>();


        static {
            // Initialize the reverse lookup table.
            for (TYPE t : TYPE.values()) {
                INVERSE_LUT.put(t.value, t);
            }
        }

        /**
         * The value of this DNS record type.
         */
        private final int value;


        /**
         * Create a new record type.
         *
         * @param value The binary value of this type.
         */
        TYPE(int value) {
            this.value = value;
        }

        /**
         * Retrieve the symbolic type of the binary value.
         *
         * @param value The binary type value.
         * @return The symbolic tpye.
         */
        public static TYPE getType(int value) {
            TYPE type = INVERSE_LUT.get(value);
            if (type == null) return UNKNOWN;
            return type;
        }

        /**
         * Retrieve the binary value of this type.
         *
         * @return The binary value.
         */
        public int getValue() {
            return value;
        }

    }

    /**
     * The symbolic class of a DNS record (usually {@link CLASS#IN} for Internet).
     *
     * @see <a href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2">IANA Domain Name System (DNS) Parameters - DNS CLASSes</a>
     */
    public enum CLASS {

        /**
         * The Internet class. This is the most common class used by todays DNS systems.
         */
        IN(1),

        /**
         * The Chaos class.
         */
        CH(3),

        /**
         * The Hesiod class.
         */
        HS(4),
        NONE(254),
        ANY(255);

        /**
         * Internal reverse lookup table to map binary class values to symbolic
         * names.
         */
        private static final HashMap<Integer, CLASS> INVERSE_LUT = new HashMap<>();

        static {
            // Initialize the interal reverse lookup table.
            for (CLASS c : CLASS.values()) {
                INVERSE_LUT.put(c.value, c);
            }
        }

        /**
         * The binary value of this dns class.
         */
        private final int value;

        /**
         * Create a new DNS class based on a binary value.
         *
         * @param value The binary value of this DNS class.
         */
        CLASS(int value) {
            this.value = value;
        }

        /**
         * Retrieve the symbolic DNS class for a binary class value.
         *
         * @param value The binary DNS class value.
         * @return The symbolic class instance.
         */
        public static CLASS getClass(int value) {
            return INVERSE_LUT.get(value);
        }

        /**
         * Retrieve the binary value of this DNS class.
         *
         * @return The binary value of this DNS class.
         */
        public int getValue() {
            return value;
        }

    }
}

