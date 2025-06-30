package io.github.remmerw.frey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;


/**
 * A DNS message as defined by RFC 1035. The message consists of a header and
 * 4 sections: question, answer, nameserver and addition resource record
 * section.
 *
 * @see <a href="https://www.ietf.org/rfc/rfc1035.txt">RFC 1035</a>
 */
public record DnsMessage(int id, OPCODE opcode, RESPONSE_CODE responseCode,
                         long receiveTimestamp, int optRrPosition, boolean recursionAvailable,
                         boolean qr, boolean authoritativeAnswer, boolean truncated,
                         boolean recursionDesired, boolean authenticData,
                         boolean checkingDisabled, DnsQuestion[] questions,
                         DnsRecord[] answerSection,
                         DnsRecord[] authoritySection, DnsRecord[] additionalSection) {

    private static final DnsQuestion[] QUESTIONS_EMPTY = new DnsQuestion[0];
    private static final DnsRecord[] RECORDS_EMPTY = new DnsRecord[0];


    /**
     * Build a DNS Message based on a binary DNS message.
     *
     * @param data The DNS message data.
     * @throws IOException On read errors.
     */
    static DnsMessage parse(byte[] data) throws IOException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        DataInputStream dis = new DataInputStream(bis);
        int id = dis.readUnsignedShort();
        int header = dis.readUnsignedShort();
        boolean qr = ((header >> 15) & 1) == 1;
        OPCODE opcode = OPCODE.getOpcode((header >> 11) & 0xf);
        boolean authoritativeAnswer = ((header >> 10) & 1) == 1;
        boolean truncated = ((header >> 9) & 1) == 1;
        boolean recursionDesired = ((header >> 8) & 1) == 1;
        boolean recursionAvailable = ((header >> 7) & 1) == 1;
        boolean authenticData = ((header >> 5) & 1) == 1;
        boolean checkingDisabled = ((header >> 4) & 1) == 1;
        RESPONSE_CODE responseCode = RESPONSE_CODE.getResponseCode(header & 0xf);
        long receiveTimestamp = System.currentTimeMillis();
        int questionCount = dis.readUnsignedShort();
        int answerCount = dis.readUnsignedShort();
        int nameserverCount = dis.readUnsignedShort();
        int additionalResourceRecordCount = dis.readUnsignedShort();
        DnsQuestion[] questions = new DnsQuestion[questionCount];
        for (int i = 0; i < questionCount; i++) {
            questions[i] = DnsQuestion.parse(dis, data);
        }
        DnsRecord[] answerSection = new DnsRecord[answerCount];
        for (int i = 0; i < answerCount; i++) {
            answerSection[i] = DnsRecord.parse(dis, data);
        }
        DnsRecord[] authoritySection = new DnsRecord[nameserverCount];
        for (int i = 0; i < nameserverCount; i++) {
            authoritySection[i] = DnsRecord.parse(dis, data);
        }
        DnsRecord[] additionalSection = new DnsRecord[additionalResourceRecordCount];
        for (int i = 0; i < additionalResourceRecordCount; i++) {
            additionalSection[i] = DnsRecord.parse(dis, data);
        }
        int optRrPosition = getOptRrPosition(additionalSection);

        return new DnsMessage(id, opcode, responseCode,
                receiveTimestamp, optRrPosition, recursionAvailable,
                qr, authoritativeAnswer, truncated,
                recursionDesired, authenticData,
                checkingDisabled, questions, answerSection,
                authoritySection, additionalSection);
    }

    /**
     * Constructs an normalized version of the given DnsMessage by setting the id to '0'.
     *
     * @param message the message of which normalized version should be constructed.
     */
    private static DnsMessage normalized(DnsMessage message) {
        return new DnsMessage(0, message.opcode, message.responseCode,
                message.receiveTimestamp, message.optRrPosition, message.recursionAvailable,
                message.qr, message.authoritativeAnswer, message.truncated,
                message.recursionDesired, message.authenticData,
                message.checkingDisabled, message.questions, message.answerSection,
                message.authoritySection, message.additionalSection);
    }

    private static DnsMessage create(Builder builder) {
        int id = builder.id;
        OPCODE opcode = builder.opcode;
        RESPONSE_CODE responseCode = builder.responseCode;
        long receiveTimestamp = -1;
        boolean qr = false;
        boolean authoritativeAnswer = false;
        boolean truncated = false;
        boolean recursionDesired = builder.recursionDesired;
        boolean recursionAvailable = false;
        boolean authenticData = false;
        boolean checkingDisabled = false;
        DnsQuestion[] questions;
        if (builder.questions == null) {
            questions = QUESTIONS_EMPTY;
        } else {
            questions = builder.questions;
        }

        DnsRecord[] additionalSection;

        if (builder.ednsBuilder == null) {
            additionalSection = RECORDS_EMPTY;
        } else {
            DnsEdns dnsEdns = builder.ednsBuilder.build();
            additionalSection = new DnsRecord[]{dnsEdns.asRecord()};
        }

        int optRrPosition = getOptRrPosition(additionalSection);

        if (optRrPosition != -1) {
            // Verify that there are no further OPT records but the one we already found.
            for (int i = optRrPosition + 1; i < additionalSection.length; i++) {
                if (additionalSection[i].type() == DnsRecord.TYPE.OPT) {
                    throw new IllegalArgumentException("There must be only one OPT pseudo RR in the additional section");
                }
            }
        }
        return new DnsMessage(id, opcode, responseCode,
                receiveTimestamp, optRrPosition, recursionAvailable,
                qr, authoritativeAnswer, truncated,
                recursionDesired, authenticData,
                checkingDisabled, questions, RECORDS_EMPTY,
                RECORDS_EMPTY, additionalSection);
    }

    private static int getOptRrPosition(DnsRecord[] additionalSection) {
        int optRrPosition = -1;
        for (int i = 0; i < additionalSection.length; i++) {
            DnsRecord dnsRecord = additionalSection[i];
            if (dnsRecord.type() == DnsRecord.TYPE.OPT) {
                optRrPosition = i;
                break;
            }
        }
        return optRrPosition;
    }

    public static Builder builder() {
        return new DnsMessage.Builder();
    }

    DatagramPacket asDatagram(InetAddress address) {
        byte[] bytes = serialize();
        return new DatagramPacket(bytes, bytes.length, address, 53);
    }

    void writeTo(OutputStream outputStream) throws IOException {
        byte[] bytes = serialize();
        DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
        dataOutputStream.writeShort(bytes.length);
        dataOutputStream.write(bytes);
    }


    private byte[] serialize() {


        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        DataOutputStream dos = new DataOutputStream(baos);
        int header = calculateHeaderBitmap();
        try {
            dos.writeShort((short) id);
            dos.writeShort((short) header);
            if (questions == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) questions.length);
            }
            if (answerSection == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) answerSection.length);
            }
            if (authoritySection == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) authoritySection.length);
            }
            if (additionalSection == null) {
                dos.writeShort(0);
            } else {
                dos.writeShort((short) additionalSection.length);
            }
            if (questions != null) {
                for (DnsQuestion question : questions) {
                    dos.write(question.toByteArray());
                }
            }
            if (answerSection != null) {
                for (DnsRecord answer : answerSection) {
                    dos.write(answer.toByteArray());
                }
            }
            if (authoritySection != null) {
                for (DnsRecord nameserverDnsRecord : authoritySection) {
                    dos.write(nameserverDnsRecord.toByteArray());
                }
            }
            if (additionalSection != null) {
                for (DnsRecord additionalResourceDnsRecord : additionalSection) {
                    dos.write(additionalResourceDnsRecord.toByteArray());
                }
            }
            dos.flush();
        } catch (IOException e) {
            // Should never happen.
            throw new AssertionError(e);
        }
        return baos.toByteArray();

    }

    private int calculateHeaderBitmap() {
        int header = 0;
        if (qr) {
            header += 1 << 15;
        }
        if (opcode != null) {
            header += opcode.getValue() << 11;
        }
        if (authoritativeAnswer) {
            header += 1 << 10;
        }
        if (truncated) {
            header += 1 << 9;
        }
        if (recursionDesired) {
            header += 1 << 8;
        }
        if (recursionAvailable) {
            header += 1 << 7;
        }
        if (authenticData) {
            header += 1 << 5;
        }
        if (checkingDisabled) {
            header += 1 << 4;
        }
        if (responseCode != null) {
            header += responseCode.getValue();
        }
        return header;
    }

    DnsQuestion getQuestion() {
        return questions[0];
    }


    /**
     * Get the minimum TTL from all answers in seconds.
     *
     * @return the minimum TTL from all answers in seconds.
     */
    long getAnswersMinTtl() {
        long answersMinTtlCache = Long.MAX_VALUE;
        for (DnsRecord r : answerSection) {
            answersMinTtlCache = Math.min(answersMinTtlCache, r.ttl());
        }
        return answersMinTtlCache;
    }


    DnsMessage asNormalizedVersion() {
        return DnsMessage.normalized(this);
    }

    @Override
    public int hashCode() {
        byte[] bytes = serialize();
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof DnsMessage otherDnsMessage)) {
            return false;
        }
        if (other == this) {
            return true;
        }
        byte[] otherBytes = otherDnsMessage.serialize();
        byte[] myBytes = serialize();
        return Arrays.equals(myBytes, otherBytes);
    }

    /**
     * Possible DNS response codes.
     *
     * @see <a href=
     * "http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6">
     * IANA Domain Name System (DNS) Paramters - DNS RCODEs</a>
     * @see <a href="http://tools.ietf.org/html/rfc6895#section-2.3">RFC 6895 § 2.3</a>
     */
    public enum RESPONSE_CODE {
        NO_ERROR(0),
        FORMAT_ERR(1),
        SERVER_FAIL(2),
        NX_DOMAIN(3),
        NO_IMP(4),
        REFUSED(5),
        YXDOMAIN(6),
        YXRRSET(7),
        NXRRSET(8),
        NOT_AUTH(9),
        NOT_ZONE(10),
        BADVERS_BADSIG(16),
        BADKEY(17),
        BADTIME(18),
        BADMODE(19),
        BADNAME(20),
        BADALG(21),
        BADTRUNC(22),
        BADCOOKIE(23),
        ;

        /**
         * Reverse lookup table for response codes.
         */
        private static final Map<Integer, RESPONSE_CODE> INVERSE_LUT = new HashMap<>(RESPONSE_CODE.values().length);

        static {
            for (RESPONSE_CODE responseCode : RESPONSE_CODE.values()) {
                INVERSE_LUT.put((int) responseCode.value, responseCode);
            }
        }

        /**
         * The response code value.
         */
        private final byte value;

        /**
         * Create a new response code.
         *
         * @param value The response code value.
         */
        RESPONSE_CODE(int value) {
            this.value = (byte) value;
        }

        /**
         * Retrieve the response code for a byte value.
         *
         * @param value The byte value.
         * @return The symbolic response code or null.
         * @throws IllegalArgumentException if the value is not in the range of 0..15.
         */
        static RESPONSE_CODE getResponseCode(int value) throws IllegalArgumentException {
            if (value < 0 || value > 65535) {
                throw new IllegalArgumentException();
            }
            return INVERSE_LUT.get(value);
        }

        /**
         * Retrieve the byte value of the response code.
         *
         * @return the response code.
         */
        byte getValue() {
            return value;
        }

    }

    /**
     * Symbolic DNS Opcode values.
     *
     * @see <a href=
     * "http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5">
     * IANA Domain Name System (DNS) Paramters - DNS OpCodes</a>
     */
    public enum OPCODE {
        QUERY,
        INVERSE_QUERY,
        STATUS,
        UNASSIGNED3,
        NOTIFY,
        UPDATE,
        ;

        /**
         * Lookup table for for opcode resolution.
         */
        private static final OPCODE[] INVERSE_LUT = new OPCODE[OPCODE.values().length];

        static {
            for (OPCODE opcode : OPCODE.values()) {
                if (INVERSE_LUT[opcode.value] != null) {
                    throw new IllegalStateException();
                }
                INVERSE_LUT[opcode.value] = opcode;
            }
        }

        /**
         * The value of this opcode.
         */
        private final byte value;

        /**
         * Create a new opcode for a given byte value.
         */
        OPCODE() {
            this.value = (byte) this.ordinal();
        }

        /**
         * Retrieve the symbolic name of an opcode byte.
         *
         * @param value The byte value of the opcode.
         * @return The symbolic opcode or null.
         * @throws IllegalArgumentException If the byte value is not in the
         *                                  range 0..15.
         */
        static OPCODE getOpcode(int value) throws IllegalArgumentException {
            if (value < 0 || value > 15) {
                throw new IllegalArgumentException();
            }
            if (value >= INVERSE_LUT.length) {
                return null;
            }
            return INVERSE_LUT[value];
        }

        /**
         * Retrieve the byte value of this opcode.
         *
         * @return The byte value of this opcode.
         */
        byte getValue() {
            return value;
        }

    }

    public static final class Builder {

        private final OPCODE opcode = OPCODE.QUERY;
        private final RESPONSE_CODE responseCode = RESPONSE_CODE.NO_ERROR;
        private int id;
        private boolean recursionDesired;

        private DnsQuestion[] questions;

        private DnsEdns.Builder ednsBuilder;

        private Builder() {
        }

        /**
         * Set the current DNS message id.
         *
         * @param id The new DNS message id.
         * @return a reference to this builder.
         */
        @SuppressWarnings("UnusedReturnValue")
        public Builder setId(int id) {
            this.id = id & 0xffff;
            return this;
        }

        /**
         * Set the recursion desired flag on this message.
         *
         * @return a reference to this builder.
         */
        @SuppressWarnings("UnusedReturnValue")
        Builder setRecursionDesired() {
            this.recursionDesired = true;
            return this;
        }


        /**
         * Set the question part of this message.
         *
         * @param dnsQuestion The question.
         * @return a reference to this builder.
         */
        @SuppressWarnings("UnusedReturnValue")
        Builder setQuestion(DnsQuestion dnsQuestion) {
            this.questions = new DnsQuestion[1];
            this.questions[0] = dnsQuestion;
            return this;
        }

        /**
         * Get the @{link EDNS} builder. If no builder has been set so far, then a new one will be created.
         * <p>
         * The EDNS record can be used to announce the supported size of UDP payload as well as additional flags.
         * </p>
         * <p>
         * Note that some networks and firewalls are known to block big UDP payloads. 1280 should be a reasonable value,
         * everything below 512 is treated as 512 and should work on all networks.
         * </p>
         *
         * @return a EDNS builder.
         */
        DnsEdns.Builder getEdnsBuilder() {
            if (ednsBuilder == null) {
                ednsBuilder = DnsEdns.builder();
            }
            return ednsBuilder;
        }

        public DnsMessage build() {
            return DnsMessage.create(this);
        }

    }

}

