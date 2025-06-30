package io.github.remmerw.frey

import kotlinx.io.Buffer
import kotlinx.io.readByteArray

/**
 * Generic payload class.
 */
interface DnsData {
    fun bytes(): ByteArray


    fun length(): Int {
        return bytes().size
    }


    fun toBuffer(buffer: Buffer) {
        buffer.write(bytes())
    }

    /**
     * OPT payload (see RFC 2671 for details).
     */

    data class OPT(val variablePart: MutableList<DnsEdns.Option>?) : DnsData {
        override fun bytes(): ByteArray {
            val dos = Buffer()
            try {
                for (endsOption in variablePart!!) {
                    endsOption.transferTo(dos)
                }
            } catch (e: Exception) {
                // Should never happen.
                throw AssertionError(e)
            }
            return dos.readByteArray()
        }

        companion object {

            fun parse(dis: Buffer, payloadLength: Int): OPT {
                val variablePart: MutableList<DnsEdns.Option>?
                if (payloadLength == 0) {
                    variablePart = mutableListOf<DnsEdns.Option>()
                } else {
                    var payloadLeft = payloadLength
                    variablePart = ArrayList<DnsEdns.Option>(4)
                    while (payloadLeft > 0) {
                        val optionCode = dis.readShort().toInt()
                        val optionLength = dis.readShort().toInt()
                        val optionData = dis.readByteArray(optionLength)
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

        private val characterStrings: List<String>
            get() {
                val extents = this.extents
                val characterStrings: MutableList<String> = mutableListOf()
                for (extent in extents) {
                    characterStrings.add(extent.decodeToString())
                }
                return characterStrings.toList()
            }

        private val extents: MutableList<ByteArray>
            get() {
                val extents = ArrayList<ByteArray>()
                var segLength: Int
                var used = 0
                while (used < blob.size) {
                    segLength = 0x00ff and blob[used].toInt()
                    val end = ++used + segLength
                    val extent = blob.copyOfRange(used, end)
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

            fun parse(dis: Buffer, length: Int): TXT {
                val blob = dis.readByteArray(length)
                return TXT(blob)
            }
        }
    }


    data class UNKNOWN(val data: ByteArray) : DnsData {
        override fun bytes(): ByteArray {
            return data
        }

        companion object {

            private fun create(dis: Buffer, payloadLength: Int): UNKNOWN {
                val data = dis.readByteArray(payloadLength)
                return UNKNOWN(data)
            }


            fun parse(dis: Buffer, payloadLength: Int): UNKNOWN {
                return create(dis, payloadLength)
            }
        }
    }
}
