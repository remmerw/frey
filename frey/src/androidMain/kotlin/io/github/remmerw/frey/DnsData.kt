package io.github.remmerw.frey

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.Collections


/**
 * Generic payload class.
 */
interface DnsData {
    fun bytes(): ByteArray


    fun length(): Int {
        return bytes().size
    }

    /**
     * Write the binary representation of this payload to the given [DataOutputStream].
     *
     * @param dos the DataOutputStream to write to.
     * @throws IOException if an I/O error occurs.
     */
    @Throws(IOException::class)
    fun toOutputStream(dos: DataOutputStream) {
        dos.write(bytes())
    }

    /**
     * OPT payload (see RFC 2671 for details).
     */
    @JvmRecord
    data class OPT(val variablePart: MutableList<DnsEdns.Option>?) : DnsData {
        override fun bytes(): ByteArray {
            val baos = ByteArrayOutputStream()
            val dos = DataOutputStream(baos)
            try {
                for (endsOption in variablePart!!) {
                    endsOption.writeToDos(dos)
                }
            } catch (e: IOException) {
                // Should never happen.
                throw AssertionError(e)
            }
            return baos.toByteArray()
        }

        companion object {
            @JvmStatic
            @Throws(IOException::class)
            fun parse(dis: DataInputStream, payloadLength: Int): OPT {
                val variablePart: MutableList<DnsEdns.Option>?
                if (payloadLength == 0) {
                    variablePart = mutableListOf<DnsEdns.Option>()
                } else {
                    var payloadLeft = payloadLength
                    variablePart = ArrayList<DnsEdns.Option>(4)
                    while (payloadLeft > 0) {
                        val optionCode = dis.readUnsignedShort()
                        val optionLength = dis.readUnsignedShort()
                        val optionData = ByteArray(optionLength)
                        dis.read(optionData)
                        val option = DnsEdns.Option.parse(optionCode, optionData)
                        variablePart.add(option)
                        payloadLeft -= 2 + 2 + optionLength
                        // Assert that payloadLeft never becomes negative
                        assert(payloadLeft >= 0)
                    }
                }

                return OPT(variablePart)
            }
        }
    }

    /**
     * A TXT record. Actually a binary blob containing extents, each of which is a one-byte count
     * followed by that many bytes of data, which can usually be interpreted as ASCII strings
     * but not always.
     */
    @JvmRecord
    data class TXT(val blob: ByteArray) : DnsData {
        val text: String
            get() {
                val sb = StringBuilder()
                val it =
                    this.characterStrings.iterator()
                while (it.hasNext()) {
                    sb.append(it.next())
                    if (it.hasNext()) {
                        sb.append(" / ")
                    }
                }
                return sb.toString()
            }

        private val characterStrings: MutableList<String?>
            get() {
                val extents = this.extents
                val characterStrings: MutableList<String?> =
                    ArrayList<String?>(extents.size)
                for (extent in extents) {
                    characterStrings.add(
                        String(
                            extent!!,
                            StandardCharsets.UTF_8
                        )
                    )
                }
                return Collections.unmodifiableList<String?>(characterStrings)
            }

        private val extents: MutableList<ByteArray?>
            get() {
                val extents =
                    ArrayList<ByteArray?>()
                var segLength: Int
                var used = 0
                while (used < blob!!.size) {
                    segLength = 0x00ff and blob[used].toInt()
                    val end = ++used + segLength
                    val extent = Arrays.copyOfRange(blob, used, end)
                    extents.add(extent)
                    used += segLength
                }
                return extents
            }


        override fun toString(): String {
            return "\"" + this.text + "\""
        }

        override fun bytes(): ByteArray {
            return blob
        }

        companion object {
            @JvmStatic
            @Throws(IOException::class)
            fun parse(dis: DataInputStream, length: Int): TXT {
                val blob = ByteArray(length)
                dis.readFully(blob)
                return TXT(blob)
            }
        }
    }


    @JvmRecord
    data class UNKNOWN(val data: ByteArray) : DnsData {
        override fun bytes(): ByteArray {
            return data
        }

        companion object {
            @Throws(IOException::class)
            private fun create(dis: DataInputStream, payloadLength: Int): UNKNOWN {
                val data = ByteArray(payloadLength)
                dis.readFully(data)
                return UNKNOWN(data)
            }

            @JvmStatic
            @Throws(IOException::class)
            fun parse(dis: DataInputStream, payloadLength: Int): UNKNOWN {
                return create(dis, payloadLength)
            }
        }
    }
}
