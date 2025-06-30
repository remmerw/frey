package io.github.remmerw.frey

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * A DNS question (request).
 */
@JvmRecord
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
        val baos = ByteArrayOutputStream(512)
        val dos = DataOutputStream(baos)

        try {
            name!!.writeToStream(dos)
            dos.writeShort(type!!.value)
            dos.writeShort(clazz!!.value or (if (unicastQuery) (1 shl 15) else 0))
            dos.flush()
        } catch (e: Exception) {
            // Should never happen
            throw RuntimeException(e)
        }
        return baos.toByteArray()
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
        fun parse(dis: DataInputStream, data: ByteArray): DnsQuestion {
            return DnsQuestion(
                DnsName.parse(dis, data),
                DnsRecord.TYPE.Companion.getType(dis.readUnsignedShort()),
                DnsRecord.CLASS.Companion.getClass(dis.readUnsignedShort()), false
            )
        }
    }
}

