package io.github.remmerw.frey

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * A DNS question (request).
 */

data class DnsQuestion(
    val name: DnsName?, val type: DnsRecord.TYPE?, val clazz: DnsRecord.CLASS?,
    val unicastQuery: Boolean
) {
    /**
     * Generate a binary paket for this dns question.
     *
     * @return The dns question.
     */
    fun toByteArray(): ByteArray {
        val buffer = Buffer()
        name!!.toBuffer(buffer)
        buffer.writeShort(type!!.value.toShort())
        buffer.writeShort((clazz!!.value or (if (unicastQuery) (1 shl 15) else 0)).toShort())
        buffer.flush()
        return buffer.readByteArray()
    }


    companion object {
        fun create(name: DnsName, type: DnsRecord.TYPE): DnsQuestion {
            checkNotNull(name)
            checkNotNull(type)
            return DnsQuestion(name, type, DnsRecord.CLASS.IN, false)
        }


        /**
         * Parse a byte array and rebuild the dns question from it.
         *
         * @param dis  The input stream.
         * @param data The plain data (for dns name references).

         */
        fun parse(dis: Buffer, data: ByteArray): DnsQuestion {
            return DnsQuestion(
                DnsName.parse(dis, data),
                DnsRecord.TYPE.Companion.getType(dis.readShort().toInt()),
                DnsRecord.CLASS.Companion.getClass(dis.readShort().toInt()), false
            )
        }
    }
}

