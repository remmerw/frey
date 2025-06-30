package io.github.remmerw.frey

import io.github.remmerw.frey.DnsData.OPT
import kotlinx.io.Buffer


/**
 * EDNS - Extension Mechanism for DNS.
 *
 * @see [RFC 6891 - Extension Mechanisms for DNS
](https://tools.ietf.org/html/rfc6891) */

data class DnsEdns(
    val udpPayloadSize: Int, val extendedRcode: Int, val version: Int,
    val flags: Int, val variablePart: MutableList<Option>
) {
    fun asRecord(): DnsRecord {
        var optFlags = flags.toLong()
        optFlags = optFlags or (extendedRcode.toLong() shl 8)
        optFlags = optFlags or (version.toLong() shl 16)
        return DnsRecord.create(
            DnsName.root(), DnsRecord.TYPE.OPT,
            udpPayloadSize, optFlags, OPT(variablePart)
        )
    }


    /**
     * The EDNS option code.
     *
     * @see [IANA - DNS EDNS0 Option Codes
    ](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.dns-parameters-11) */
    enum class OptionCode(val asInt: Int) {
        UNKNOWN(-1),
        NSID(3),
        ;

        companion object {
            private val INVERSE_LUT: MutableMap<Int?, OptionCode?> = HashMap<Int?, OptionCode?>(
                entries.size
            )

            init {
                for (optionCode in entries) {
                    INVERSE_LUT.put(optionCode.asInt, optionCode)
                }
            }

            fun from(optionCode: Int): OptionCode {
                var res = INVERSE_LUT.get(optionCode)
                if (res == null) res = UNKNOWN
                return res
            }
        }
    }

    class EdnsBuilder() {
        var udpPayloadSize = 0
        var dnssecOk = false


        fun setUdpPayloadSize(udpPayloadSize: Int): EdnsBuilder {
            require(udpPayloadSize <= 0xffff) { "UDP payload size must not be greater than 65536, was " + udpPayloadSize }
            this.udpPayloadSize = udpPayloadSize
            return this
        }

        fun setDnssecOk(dnssecOk: Boolean): EdnsBuilder {
            this.dnssecOk = dnssecOk
            return this
        }

        fun build(): DnsEdns {
            return create(this)
        }
    }


    data class Option(val optionCode: Int, val optionLength: Int, val optionData: ByteArray) {

        fun transferTo(buffer: Buffer) {
            buffer.writeShort(optionCode.toShort())
            buffer.writeShort(optionLength.toShort())
            buffer.write(optionData)
        }


        companion object {
            fun create(optionCode: Int, optionData: ByteArray): Option {
                return Option(optionCode, optionData.size, optionData)
            }

            fun create(optionData: ByteArray, optionCode: OptionCode): Option {
                return Option(optionCode.asInt, optionData.size, optionData)
            }

            fun parse(intOptionCode: Int, optionData: ByteArray): Option {
                val optionCode = OptionCode.Companion.from(intOptionCode)
                val res: Option
                if (optionCode == OptionCode.NSID) {
                    res = create(optionData, optionCode)
                } else {
                    res = create(intOptionCode, optionData)
                }
                return res
            }
        }
    }

    companion object {
        /**
         * Inform the dns server that the client supports DNSSEC.
         */
        private const val FLAG_DNSSEC_OK = 0x8000
        private val VARIABLE_PART: MutableList<Option> = ArrayList<Option>()


        private fun create(builder: EdnsBuilder): DnsEdns {
            var flags = 0
            if (builder.dnssecOk) {
                flags = flags or FLAG_DNSSEC_OK
            }
            return DnsEdns(builder.udpPayloadSize, 0, 0, flags, VARIABLE_PART)
        }

        fun builder(): EdnsBuilder {
            return EdnsBuilder()
        }
    }
}
