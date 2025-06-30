package io.github.remmerw.frey

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.InetAddress

/**
 * A DNS message as defined by RFC 1035. The message consists of a header and
 * 4 sections: question, answer, nameserver and addition resource record
 * section.
 *
 * @see [RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)
 */
@JvmRecord
data class DnsMessage(
    val id: Int, val opcode: OPCODE?, val responseCode: RESPONSE_CODE?,
    val receiveTimestamp: Long, val optRrPosition: Int, val recursionAvailable: Boolean,
    val qr: Boolean, val authoritativeAnswer: Boolean, val truncated: Boolean,
    val recursionDesired: Boolean, val authenticData: Boolean,
    val checkingDisabled: Boolean, val questions: List<DnsQuestion>?,
    val answerSection: List<DnsRecord>,
    val authoritySection: List<DnsRecord>?, val additionalSection: List<DnsRecord>?
) {
    fun asDatagram(address: InetAddress?): DatagramPacket {
        val bytes = serialize()
        return DatagramPacket(bytes, bytes.size, address, 53)
    }


    fun writeTo(outputStream: OutputStream?) {
        val bytes = serialize()
        val dataOutputStream = DataOutputStream(outputStream)
        dataOutputStream.writeShort(bytes.size)
        dataOutputStream.write(bytes)
    }


    private fun serialize(): ByteArray {
        val baos = ByteArrayOutputStream(512)
        val dos = DataOutputStream(baos)
        val header = calculateHeaderBitmap()
        try {
            dos.writeShort(id.toShort().toInt())
            dos.writeShort(header.toShort().toInt())
            if (questions == null) {
                dos.writeShort(0)
            } else {
                dos.writeShort(questions.size.toShort().toInt())
            }
            if (answerSection == null) {
                dos.writeShort(0)
            } else {
                dos.writeShort(answerSection.size.toShort().toInt())
            }
            if (authoritySection == null) {
                dos.writeShort(0)
            } else {
                dos.writeShort(authoritySection.size.toShort().toInt())
            }
            if (additionalSection == null) {
                dos.writeShort(0)
            } else {
                dos.writeShort(additionalSection.size.toShort().toInt())
            }
            if (questions != null) {
                for (question in questions) {
                    dos.write(question.toByteArray())
                }
            }
            if (answerSection != null) {
                for (answer in answerSection) {
                    dos.write(answer.toByteArray())
                }
            }
            if (authoritySection != null) {
                for (nameserverDnsRecord in authoritySection) {
                    dos.write(nameserverDnsRecord.toByteArray())
                }
            }
            if (additionalSection != null) {
                for (additionalResourceDnsRecord in additionalSection) {
                    dos.write(additionalResourceDnsRecord.toByteArray())
                }
            }
            dos.flush()
        } catch (e: Exception) {
            // Should never happen.
            throw AssertionError(e)
        }
        return baos.toByteArray()
    }

    private fun calculateHeaderBitmap(): Int {
        var header = 0
        if (qr) {
            header += 1 shl 15
        }
        if (opcode != null) {
            header += opcode.value.toInt() shl 11
        }
        if (authoritativeAnswer) {
            header += 1 shl 10
        }
        if (truncated) {
            header += 1 shl 9
        }
        if (recursionDesired) {
            header += 1 shl 8
        }
        if (recursionAvailable) {
            header += 1 shl 7
        }
        if (authenticData) {
            header += 1 shl 5
        }
        if (checkingDisabled) {
            header += 1 shl 4
        }
        if (responseCode != null) {
            header += responseCode.value.toInt()
        }
        return header
    }

    val question: DnsQuestion
        get() = questions!![0]


    val answersMinTtl: Long
        /**
         * Get the minimum TTL from all answers in seconds.
         *
         * @return the minimum TTL from all answers in seconds.
         */
        get() {
            var answersMinTtlCache = java.lang.Long.MAX_VALUE
            for (r in answerSection!!) {
                answersMinTtlCache = Math.min(answersMinTtlCache, r.ttl)
            }
            return answersMinTtlCache
        }


    fun asNormalizedVersion(): DnsMessage {
        return normalized(this)
    }

    override fun hashCode(): Int {
        val bytes = serialize()
        return bytes.hashCode()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is DnsMessage) {
            return false
        }
        if (other === this) {
            return true
        }
        val otherBytes = other.serialize()
        val myBytes = serialize()
        return myBytes.contentEquals(otherBytes)
    }

    /**
     * Possible DNS response codes.
     *
     * @see [
     * IANA Domain Name System
     * @see [RFC 6895 § 2.3](http://tools.ietf.org/html/rfc6895.section-2.3)
    ](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.dns-parameters-6) */
    enum class RESPONSE_CODE(value: Int) {
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
         * Retrieve the byte value of the response code.
         *
         * @return the response code.
         */
        /**
         * The response code value.
         */
        val value: Byte

        /**
         * Create a new response code.
         *
         * @param value The response code value.
         */
        init {
            this.value = value.toByte()
        }

        companion object {
            /**
             * Reverse lookup table for response codes.
             */
            private val INVERSE_LUT: MutableMap<Int?, RESPONSE_CODE?> =
                HashMap<Int?, RESPONSE_CODE?>(
                    entries.size
                )

            init {
                for (responseCode in entries) {
                    INVERSE_LUT.put(responseCode.value.toInt(), responseCode)
                }
            }

            /**
             * Retrieve the response code for a byte value.
             *
             * @param value The byte value.
             * @return The symbolic response code or null.
             * @throws IllegalArgumentException if the value is not in the range of 0..15.
             */
            @Throws(IllegalArgumentException::class)
            fun getResponseCode(value: Int): RESPONSE_CODE? {
                require(!(value < 0 || value > 65535))
                return INVERSE_LUT.get(value)
            }
        }
    }

    /**
     * Symbolic DNS Opcode values.
     *
     * @see [
     * IANA Domain Name System
    ](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.dns-parameters-5) */
    enum class OPCODE {
        QUERY,
        INVERSE_QUERY,
        STATUS,
        UNASSIGNED3,
        NOTIFY,
        UPDATE,
        ;

        /**
         * Retrieve the byte value of this opcode.
         *
         * @return The byte value of this opcode.
         */
        /**
         * The value of this opcode.
         */
        val value: Byte

        /**
         * Create a new opcode for a given byte value.
         */
        init {
            this.value = this.ordinal.toByte()
        }

        companion object {
            /**
             * Lookup table for for opcode resolution.
             */
            private val INVERSE_LUT = arrayOfNulls<OPCODE>(entries.size)

            init {
                for (opcode in entries) {
                    check(INVERSE_LUT[opcode.value.toInt()] == null)
                    INVERSE_LUT[opcode.value.toInt()] = opcode
                }
            }

            /**
             * Retrieve the symbolic name of an opcode byte.
             *
             * @param value The byte value of the opcode.
             * @return The symbolic opcode or null.
             * @throws IllegalArgumentException If the byte value is not in the
             * range 0..15.
             */
            @Throws(IllegalArgumentException::class)
            fun getOpcode(value: Int): OPCODE? {
                require(!(value < 0 || value > 15))
                if (value >= INVERSE_LUT.size) {
                    return null
                }
                return INVERSE_LUT[value]
            }
        }
    }

    class Builder() {
        val opcode = OPCODE.QUERY
        val responseCode = RESPONSE_CODE.NO_ERROR
        var id = 0
        var recursionDesired = false

        var questions: List<DnsQuestion>? = null

        /**
         * Get the @{link EDNS} builder. If no builder has been set so far, then a new one will be created.
         *
         *
         * The EDNS record can be used to announce the supported size of UDP payload as well as additional flags.
         *
         *
         *
         * Note that some networks and firewalls are known to block big UDP payloads. 1280 should be a reasonable value,
         * everything below 512 is treated as 512 and should work on all networks.
         *
         *
         * @return a EDNS builder.
         */
        val ednsBuilder: DnsEdns.EdnsBuilder = DnsEdns.builder()

        /**
         * Set the current DNS message id.
         *
         * @param id The new DNS message id.
         * @return a reference to this builder.
         */
        fun setId(id: Int): Builder {
            this.id = id and 0xffff
            return this
        }

        /**
         * Set the recursion desired flag on this message.
         *
         * @return a reference to this builder.
         */
        fun setRecursionDesired(): Builder {
            this.recursionDesired = true
            return this
        }


        /**
         * Set the question part of this message.
         *
         * @param dnsQuestion The question.
         * @return a reference to this builder.
         */
        fun setQuestion(dnsQuestion: DnsQuestion): Builder {
            this.questions = listOf(dnsQuestion)
            return this
        }


        fun build(): DnsMessage {
            return create(this)
        }
    }

    companion object {
        private val QUESTIONS_EMPTY: List<DnsQuestion> = emptyList()
        private val RECORDS_EMPTY: List<DnsRecord> = emptyList()


        /**
         * Build a DNS Message based on a binary DNS message.
         *
         * @param data The DNS message data.
         */

        fun parse(data: ByteArray): DnsMessage {
            val bis = ByteArrayInputStream(data)
            val dis = DataInputStream(bis)
            val id = dis.readUnsignedShort()
            val header = dis.readUnsignedShort()
            val qr = ((header shr 15) and 1) == 1
            val opcode = OPCODE.Companion.getOpcode((header shr 11) and 0xf)
            val authoritativeAnswer = ((header shr 10) and 1) == 1
            val truncated = ((header shr 9) and 1) == 1
            val recursionDesired = ((header shr 8) and 1) == 1
            val recursionAvailable = ((header shr 7) and 1) == 1
            val authenticData = ((header shr 5) and 1) == 1
            val checkingDisabled = ((header shr 4) and 1) == 1
            val responseCode = RESPONSE_CODE.Companion.getResponseCode(header and 0xf)
            val receiveTimestamp = System.currentTimeMillis()
            val questionCount = dis.readUnsignedShort()
            val answerCount = dis.readUnsignedShort()
            val nameserverCount = dis.readUnsignedShort()
            val additionalResourceRecordCount = dis.readUnsignedShort()
            val questions: MutableList<DnsQuestion> = mutableListOf()
            for (i in 0..<questionCount) {
                questions.add(DnsQuestion.Companion.parse(dis, data))
            }
            val answerSection: MutableList<DnsRecord> = mutableListOf()
            for (i in 0..<answerCount) {
                answerSection.add(DnsRecord.Companion.parse(dis, data))
            }
            val authoritySection: MutableList<DnsRecord> = mutableListOf()
            for (i in 0..<nameserverCount) {
                authoritySection.add(DnsRecord.Companion.parse(dis, data))
            }
            val additionalSection: MutableList<DnsRecord> =
                mutableListOf()
            for (i in 0..<additionalResourceRecordCount) {
                additionalSection.add(DnsRecord.Companion.parse(dis, data))
            }
            val optRrPosition: Int = getOptRrPosition(additionalSection)

            return DnsMessage(
                id, opcode, responseCode,
                receiveTimestamp, optRrPosition, recursionAvailable,
                qr, authoritativeAnswer, truncated,
                recursionDesired, authenticData,
                checkingDisabled, questions, answerSection,
                authoritySection, additionalSection
            )
        }

        /**
         * Constructs an normalized version of the given DnsMessage by setting the id to '0'.
         *
         * @param message the message of which normalized version should be constructed.
         */
        private fun normalized(message: DnsMessage): DnsMessage {
            return DnsMessage(
                0, message.opcode, message.responseCode,
                message.receiveTimestamp, message.optRrPosition, message.recursionAvailable,
                message.qr, message.authoritativeAnswer, message.truncated,
                message.recursionDesired, message.authenticData,
                message.checkingDisabled, message.questions, message.answerSection,
                message.authoritySection, message.additionalSection
            )
        }

        private fun create(builder: Builder): DnsMessage {
            val id = builder.id
            val opcode = builder.opcode
            val responseCode = builder.responseCode
            val receiveTimestamp: Long = -1
            val qr = false
            val authoritativeAnswer = false
            val truncated = false
            val recursionDesired = builder.recursionDesired
            val recursionAvailable = false
            val authenticData = false
            val checkingDisabled = false
            val questions: List<DnsQuestion>
            if (builder.questions == null) {
                questions = QUESTIONS_EMPTY
            } else {
                questions = builder.questions!!
            }

            val additionalSection: List<DnsRecord>

            if (builder.ednsBuilder == null) {
                additionalSection = RECORDS_EMPTY
            } else {
                val dnsEdns = builder.ednsBuilder!!.build()
                additionalSection = listOf(dnsEdns.asRecord())
            }

            val optRrPosition: Int = getOptRrPosition(additionalSection)

            if (optRrPosition != -1) {
                // Verify that there are no further OPT records but the one we already found.
                for (i in optRrPosition + 1..<additionalSection.size) {
                    require(additionalSection[i].type != DnsRecord.TYPE.OPT) { "There must be only one OPT pseudo RR in the additional section" }
                }
            }
            return DnsMessage(
                id, opcode, responseCode,
                receiveTimestamp, optRrPosition, recursionAvailable,
                qr, authoritativeAnswer, truncated,
                recursionDesired, authenticData,
                checkingDisabled, questions, RECORDS_EMPTY,
                RECORDS_EMPTY, additionalSection
            )
        }

        private fun getOptRrPosition(additionalSection: List<DnsRecord>): Int {
            var optRrPosition = -1
            for (i in additionalSection.indices) {
                val dnsRecord = additionalSection[i]
                if (dnsRecord.type == DnsRecord.TYPE.OPT) {
                    optRrPosition = i
                    break
                }
            }
            return optRrPosition
        }

        fun builder(): Builder {
            return Builder()
        }
    }
}

