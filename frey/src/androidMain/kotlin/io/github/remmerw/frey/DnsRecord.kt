package io.github.remmerw.frey

import io.github.remmerw.frey.DnsData.TXT
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.OutputStream

/**
 * A generic DNS record.
 */
@JvmRecord
data class DnsRecord(
    val name: DnsName, val type: TYPE?, val clazz: CLASS?, val clazzValue: Int, val ttl: Long,
    /**
     * The payload data, usually a subclass of data (A, AAAA, CNAME, ...).
     *
     * @return The payload data.
     */
    val payload: DnsData?
) {

    private fun toOutputStream(outputStream: OutputStream?) {
        checkNotNull(this.payload) { "Empty Record has no byte representation" }

        val dos = DataOutputStream(outputStream)

        name!!.writeToStream(dos)
        dos.writeShort(type!!.value)
        dos.writeShort(clazzValue)
        dos.writeInt(ttl.toInt())

        dos.writeShort(payload.length())
        payload.toOutputStream(dos)
    }

    fun toByteArray(): ByteArray {
        val totalSize = (name!!.size()
                + 10 // 2 byte short type + 2 byte short classValue + 4 byte int ttl + 2 byte short payload length.
                + payload!!.length())
        val baos = ByteArrayOutputStream(totalSize)
        val dos = DataOutputStream(baos)
        try {
            toOutputStream(dos)
        } catch (e: Exception) {
            // Should never happen.
            throw AssertionError(e)
        }
        return baos.toByteArray()
    }

    /**
     * Retrieve a textual representation of this resource record.
     *
     * @return String
     */
    override fun toString(): String {
        return name.rawAce + ".\t" + ttl + '\t' + clazz + '\t' + type + '\t' + this.payload
    }

    /**
     * Check if this record answers a given query.
     *
     * @param q The query.
     * @return True if this record is a valid answer.
     */
    fun isAnswer(q: DnsQuestion): Boolean {
        return ((q.type == type) || (q.type == TYPE.ANY)) &&
                ((q.clazz == clazz) || (q.clazz == CLASS.ANY)) &&
                q.name == name
    }

    override fun equals(other: Any?): Boolean {
        if (other !is DnsRecord) {
            return false
        }
        if (other === this) {
            return true
        }
        if (!name!!.equals(other.name)) return false
        if (type != other.type) return false
        if (clazz != other.clazz) return false
        // Note that we do not compare the TTL here, since we consider two Records with everything but the TTL equal to
        // be equal too.
        return this.payload == other.payload
    }


    /**
     * The resource record type.
     *
     * @see [
     * IANA DNS Parameters - Resource Record
    ](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.dns-parameters-4) */
    enum class TYPE
    /**
     * Create a new record type.
     *
     * @param value The binary value of this type.
     */(
        /**
         * The value of this DNS record type.
         */
        val value: Int
    ) {
        UNKNOWN(-1),
        A(1),
        TXT(16),
        OPT(41),
        ANY(255),
        AAAA(28),
        ;

        /**
         * Retrieve the binary value of this type.
         *
         * @return The binary value.
         */


        companion object {
            /**
             * Internal lookup table to map values to types.
             */
            private val INVERSE_LUT: MutableMap<Int, TYPE> = mutableMapOf()


            init {
                // Initialize the reverse lookup table.
                for (t in entries) {
                    INVERSE_LUT.put(t.value, t)
                }
            }

            /**
             * Retrieve the symbolic type of the binary value.
             *
             * @param value The binary type value.
             * @return The symbolic tpye.
             */
            fun getType(value: Int): TYPE {
                val type: TYPE? = INVERSE_LUT[value]
                if (type == null) return UNKNOWN
                return type
            }
        }
    }

    /**
     * The symbolic class of a DNS record (usually [CLASS.IN] for Internet).
     *
     * @see [IANA Domain Name System
    ](http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml.dns-parameters-2) */
    enum class CLASS
    /**
     * Create a new DNS class based on a binary value.
     *
     * @param value The binary value of this DNS class.
     */(
        /**
         * The binary value of this dns class.
         */
        val value: Int
    ) {
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
         * Retrieve the binary value of this DNS class.
         *
         * @return The binary value of this DNS class.
         */

        companion object {
            /**
             * Internal reverse lookup table to map binary class values to symbolic
             * names.
             */
            private val INVERSE_LUT = HashMap<Int?, CLASS?>()

            init {
                // Initialize the interal reverse lookup table.
                for (c in entries) {
                    INVERSE_LUT.put(c.value, c)
                }
            }

            /**
             * Retrieve the symbolic DNS class for a binary class value.
             *
             * @param value The binary DNS class value.
             * @return The symbolic class instance.
             */
            fun getClass(value: Int): CLASS? {
                return INVERSE_LUT.get(value)
            }
        }
    }

    companion object {
        fun create(
            name: DnsName,
            type: TYPE?,
            clazzValue: Int,
            ttl: Long,
            payloadDnsData: DnsData?
        ): DnsRecord {
            return DnsRecord(name, type, CLASS.NONE, clazzValue, ttl, payloadDnsData)
        }

        /**
         * Parse a given record based on the full message data and the current
         * stream position.
         *
         * @param dis  The DataInputStream positioned at the first record byte.
         * @param data The full message data.
         * @return the record which was parsed.
         */

        fun parse(dis: DataInputStream, data: ByteArray): DnsRecord {
            val name = DnsName.parse(dis, data)
            val typeValue = dis.readUnsignedShort()
            val type: TYPE = TYPE.Companion.getType(typeValue)
            val clazzValue = dis.readUnsignedShort()
            val clazz: CLASS? = CLASS.Companion.getClass(clazzValue and 0x7fff)
            val ttl = ((dis.readUnsignedShort().toLong()) shl 16) +
                    dis.readUnsignedShort()
            val payloadLength = dis.readUnsignedShort()
            val payloadDnsData: DnsData = when (type) {
                TYPE.TXT -> TXT.parse(dis, payloadLength)
                TYPE.OPT -> DnsData.OPT.parse(dis, payloadLength)
                else -> DnsData.UNKNOWN.parse(dis, payloadLength)
            }
            return DnsRecord(name, type, clazz, clazzValue, ttl, payloadDnsData)
        }
    }
}

