package io.github.remmerw.frey

import kotlinx.io.Buffer
import java.io.DataInputStream


/**
 * A DNS name, also called "domain name". A DNS name consists of multiple 'labels' (see [DnsLabel]) and is subject to certain restrictions (see
 * for example [RFC 3696 § 2.](https://tools.ietf.org/html/rfc3696#section-2)).
 *
 *
 * Instances of this class can be created by using [.from].
 *
 *
 *
 * This class holds three representations of a DNS name: ACE, raw ACE and IDN. ACE (ASCII Compatible Encoding), which
 * can be accessed via [.ace], represents mostly the data that got send over the wire. But since DNS names are
 * case insensitive, the ACE value is normalized to lower case. You can use [.getRawAce] to get the raw ACE data
 * that was received, which possibly includes upper case characters. The IDN (Internationalized Domain Name), that is
 * the DNS name as it should be shown to the user, can be retrieved using .
 *
 * More information about Internationalized Domain Names can be found at:
 *
 *  * [UTS #46 - Unicode IDNA Compatibility Processing](https://unicode.org/reports/tr46/)
 *  * [RFC 8753 - Internationalized Domain Names for Applications (IDNA) Review for New Unicode Versions](https://tools.ietf.org/html/rfc8753)
 *
 *
 * @author Florian Schmaus
 * @see [RFC 3696](https://tools.ietf.org/html/rfc3696)
 *
 * @see DnsLabel
 */
data class DnsName(
    val ace: String,
    /**
     * Returns the raw ACE version of this DNS name. That is, the version as it was
     * received over the wire. Most notably, this version may include uppercase
     * letters.
     *
     *
     * **Please refer  for a discussion of the security
     * implications when working with the ACE representation of a DNS name.**
     *
     * @return the raw ACE version of this DNS name.
     */
    val rawAce: String,
    val labels: MutableList<DnsLabel>,
    val rawLabels: MutableList<DnsLabel>
) : Comparable<DnsName> {


    fun toBuffer(buffer: Buffer) {
        for (i in labels.indices.reversed()) {
            labels[i].toBuffer(buffer)
        }
        buffer.writeByte(0)
    }


    fun size(): Int {
        return if (isRootLabel(ace)) {
            1
        } else {
            ace.length + 2
        }
    }

    override fun toString(): String {
        if (labels.size == 0) {
            return "."
        }

        val sb = StringBuilder()
        for (i in labels.indices.reversed()) {
            // Note that it is important that we append the result of DnsLabel.toString() to
            // the StringBuilder. As only the result of toString() is the safe label
            // representation.
            val safeLabelRepresentation = labels.get(i).toString()
            sb.append(safeLabelRepresentation)
            if (i != 0) {
                sb.append('.')
            }
        }
        return sb.toString()
    }

    override fun compareTo(other: DnsName): Int {
        return ace!!.compareTo(other.ace!!)
    }

    override fun equals(other: Any?): Boolean {
        if (other == null) return false
        if (other is DnsName) {
            return labels.stream().toArray()
                .contentEquals(other.labels.stream().toArray()) // todo check
        }
        return false
    }

    companion object {
        private val DNS_LABELS_EMPTY: MutableList<DnsLabel> = ArrayList<DnsLabel>()
        private const val MAX_LABELS = 128

        /**
         * @see [RFC 3490 § 3.1 1.](https://www.ietf.org/rfc/rfc3490.txt)
         */
        private const val LABEL_SEP_REGEX = "[.。．｡]"
        private var ROOT: DnsName? = null


        private fun create(name: String, inAce: Boolean): DnsName {
            var name = name
            val rawAce: String
            if (name.isEmpty()) {
                rawAce = root().rawAce
            } else {
                val nameLength = name.length
                val nameLastPos = nameLength - 1

                // Strip potential trailing dot. N.B. that we require nameLength > 2, because we don't want to strip the one
                // character string containing only a single dot to the empty string.
                if (nameLength >= 2 && name.get(nameLastPos) == '.') {
                    name = name.subSequence(0, nameLastPos).toString()
                }

                if (inAce) {
                    // Name is already in ACE format.
                    rawAce = name
                } else {
                    rawAce = DnsUtility.toASCII(name)
                }
            }

            val ace = rawAce.lowercase()

            val rawLabels: MutableList<DnsLabel>?
            val labels: MutableList<DnsLabel>?
            if (isRootLabel(ace)) {
                labels = DNS_LABELS_EMPTY
                rawLabels = labels
            } else {
                labels = getLabels(ace)
                rawLabels = getLabels(rawAce)
            }

            return DnsName(ace, rawAce, labels, rawLabels)
        }

        private fun create(rawLabels: MutableList<DnsLabel>): DnsName {
            val labels: MutableList<DnsLabel> = ArrayList<DnsLabel>()

            var size = 0
            for (rawLabel in rawLabels) {
                size += rawLabel.length() + 1
                labels.add(rawLabel.asLowercaseVariant())
            }

            val rawAce: String = labelsToString(rawLabels, size)
            val ace: String = labelsToString(labels, size)

            return DnsName(ace, rawAce, labels, rawLabels)
        }

        @JvmStatic
        fun root(): DnsName {
            if (ROOT == null) {
                ROOT = create(".", true)
            }
            return ROOT!!
        }

        private fun labelsToString(labels: MutableList<DnsLabel>, stringLength: Int): String {
            val sb = StringBuilder(stringLength)
            for (i in labels.indices.reversed()) {
                sb.append(labels.get(i)).append('.')
            }
            sb.setLength(sb.length - 1)
            return sb.toString()
        }

        private fun getLabels(ace: String): MutableList<DnsLabel> {
            val labels: MutableList<String> = mutableListOf()

            ace.split(
                LABEL_SEP_REGEX.toRegex(),
                MAX_LABELS.coerceAtLeast(0)
            ).forEach { text -> labels.add(text) }

            // Reverse the labels, so that 'foo, example, org' becomes 'org, example, foo'.
            for (i in 0..<labels.size / 2) {
                val t = labels[i]
                val j = labels.size - i - 1
                labels[i] = labels[j]
                labels[j] = t
            }
            return DnsLabel.from(labels)
        }


        fun from(name: CharSequence): DnsName {
            return Companion.from(name.toString())
        }

        private fun from(name: String): DnsName {
            return create(name, false)
        }

        /**
         * Create a DNS name by "concatenating" the child under the parent name. The child can also be seen as the "left"
         * part of the resulting DNS name and the parent is the "right" part.
         *
         *
         * For example using "i.am.the.child" as child and "of.this.parent.example" as parent, will result in a DNS name:
         * "i.am.the.child.of.this.parent.example".
         *
         *
         * @param child  the child DNS name.
         * @param parent the parent DNS name.
         * @return the resulting of DNS name.
         */
        private fun from(child: DnsName, parent: DnsName): DnsName {
            val rawLabels: MutableList<DnsLabel> = mutableListOf()
            rawLabels.addAll(parent.rawLabels)
            rawLabels.addAll(child.rawLabels)
            return create(rawLabels)
        }

        /**
         * Parse a domain name starting at the current offset and moving the input
         * stream pointer past this domain name (even if cross references occure).
         *
         * @param dis  The input stream.
         * @param data The raw data (for cross references).
         * @return The domain name string.
         */

        fun parse(dis: DataInputStream, data: ByteArray): DnsName {
            var c = dis.readUnsignedByte()
            if ((c and 0xc0) == 0xc0) {
                c = ((c and 0x3f) shl 8) + dis.readUnsignedByte()
                val jumps = HashSet<Int?>()
                jumps.add(c)
                return parse(data, c, jumps)
            }
            if (c == 0) {
                return root()
            }
            val b = ByteArray(c)
            dis.readFully(b)

            val childLabelString = b.decodeToString()
            val child: DnsName = create(childLabelString, true)

            val parent: DnsName = parse(dis, data)
            return from(child, parent)
        }

        /**
         * Parse a domain name starting at the given offset.
         *
         * @param data   The raw data.
         * @param offset The offset.
         * @param jumps  The list of jumps (by now).
         * @return The parsed domain name.
         * @throws IllegalStateException on cycles.
         */
        @Throws(IllegalStateException::class)
        private fun parse(data: ByteArray, offset: Int, jumps: HashSet<Int?>): DnsName {
            var c = data[offset].toInt() and 0xff
            if ((c and 0xc0) == 0xc0) {
                c = ((c and 0x3f) shl 8) + (data[offset + 1].toInt() and 0xff)
                check(!jumps.contains(c)) { "Cyclic offsets detected." }
                jumps.add(c)
                return parse(data, c, jumps)
            }
            if (c == 0) {
                return root()
            }

            val childLabelString = String(data, offset + 1, c)
            val child: DnsName = create(childLabelString, true)

            val parent: DnsName = parse(data, offset + 1 + c, jumps)
            return from(child, parent)
        }

        private fun isRootLabel(ace: String): Boolean {
            return ace.isEmpty() || ace == "."
        }
    }
}
