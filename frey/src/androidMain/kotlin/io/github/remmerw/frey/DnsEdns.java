package io.github.remmerw.frey;


import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * EDNS - Extension Mechanism for DNS.
 *
 * @see <a href="https://tools.ietf.org/html/rfc6891">RFC 6891 - Extension Mechanisms for DNS (EDNS(0))</a>
 */
public record DnsEdns(int udpPayloadSize, int extendedRcode, int version,
                      int flags, List<Option> variablePart) {

    /**
     * Inform the dns server that the client supports DNSSEC.
     */
    private static final int FLAG_DNSSEC_OK = 0x8000;
    private static final List<Option> VARIABLE_PART = new ArrayList<>();


    private static DnsEdns create(Builder builder) {
        int flags = 0;
        if (builder.dnssecOk) {
            flags |= FLAG_DNSSEC_OK;
        }
        return new DnsEdns(builder.udpPayloadSize, 0, 0, flags, VARIABLE_PART);
    }

    public static Builder builder() {
        return new Builder();
    }

    public DnsRecord asRecord() {
        long optFlags = flags;
        optFlags |= (long) extendedRcode << 8;
        optFlags |= (long) version << 16;
        return DnsRecord.create(DnsName.root(), DnsRecord.TYPE.OPT,
                udpPayloadSize, optFlags, new DnsData.OPT(variablePart));
    }


    /**
     * The EDNS option code.
     *
     * @see <a href="http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11">IANA - DNS EDNS0 Option Codes (OPT)</a>
     */
    public enum OptionCode {
        UNKNOWN(-1),
        NSID(3),
        ;

        private static final Map<Integer, OptionCode> INVERSE_LUT = new HashMap<>(OptionCode.values().length);

        static {
            for (OptionCode optionCode : OptionCode.values()) {
                INVERSE_LUT.put(optionCode.asInt, optionCode);
            }
        }

        final int asInt;

        OptionCode(int optionCode) {
            this.asInt = optionCode;
        }

        public static OptionCode from(int optionCode) {
            OptionCode res = INVERSE_LUT.get(optionCode);
            if (res == null) res = OptionCode.UNKNOWN;
            return res;
        }
    }

    public static final class Builder {
        private int udpPayloadSize;
        private boolean dnssecOk;


        private Builder() {
        }

        public Builder setUdpPayloadSize(int udpPayloadSize) {
            if (udpPayloadSize > 0xffff) {
                throw new IllegalArgumentException("UDP payload size must not be greater than 65536, was " + udpPayloadSize);
            }
            this.udpPayloadSize = udpPayloadSize;
            return this;
        }

        @SuppressWarnings("UnusedReturnValue")
        public Builder setDnssecOk(boolean dnssecOk) {
            this.dnssecOk = dnssecOk;
            return this;
        }

        public DnsEdns build() {
            return DnsEdns.create(this);
        }
    }


    public record Option(int optionCode, int optionLength, byte[] optionData) {

        static Option create(int optionCode, byte[] optionData) {
            return new Option(optionCode, optionData.length, optionData);
        }

        static Option create(byte[] optionData, OptionCode optionCode) {
            return new Option(optionCode.asInt, optionData.length, optionData);
        }

        public static Option parse(int intOptionCode, byte[] optionData) {
            OptionCode optionCode = OptionCode.from(intOptionCode);
            Option res;
            if (optionCode == OptionCode.NSID) {
                res = Option.create(optionData, optionCode);
            } else {
                res = Option.create(intOptionCode, optionData);
            }
            return res;
        }

        public void writeToDos(DataOutputStream dos) throws IOException {
            dos.writeShort(optionCode);
            dos.writeShort(optionLength);
            dos.write(optionData);
        }


    }

}
