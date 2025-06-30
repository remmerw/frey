package io.github.remmerw.frey

import kotlinx.io.Buffer


/**
 * A DNS label is an individual component of a DNS name. Labels are usually shown separated by dots.
 *
 *
 * This class implements [Comparable] which compares DNS labels according to the Canonical DNS Name Order as
 * specified in [RFC 4034 § 6.1](https://tools.ietf.org/html/rfc4034#section-6.1).
 *
 *
 *
 * Note that as per [RFC 2181 § 11](https://tools.ietf.org/html/rfc2181#section-11) DNS labels may contain
 * any byte.
 *
 *
 * @author Florian Schmaus
 * @see [RFC 5890 § 2.2. DNS-Related Terminology](https://tools.ietf.org/html/rfc5890.section-2.2)
 */

data class DnsLabel(val label: String) {
    fun length(): Int {
        return toSafeString().length
    }

    private fun toSafeString(): String {
        // The default implementation assumes that toString() returns a safe
        // representation. Subclasses may override toSafeString() if this assumption is
        // not correct.
        return toString()
    }


    override fun toString(): String {
        return toSafeRepresentation(label)
    }

    fun asLowercaseVariant(): DnsLabel {
        val lowercaseLabel = label.lowercase()
        return from(lowercaseLabel)
    }

    fun toBuffer(buffer: Buffer) {
        val byteCache: ByteArray = label.encodeToByteArray()
        buffer.writeByte(byteCache.size.toByte())
        buffer.write(byteCache, 0, byteCache.size)
    }


    companion object {
        /**
         * The maximum length of a DNS label in octets.
         *
         * @see [RFC 1035 § 2.3.4.](https://tools.ietf.org/html/rfc1035)
         */
        const val MAX_LABEL_LENGTH_IN_OCTETS: Int = 63


        fun create(label: String): DnsLabel {
            val byteCache: ByteArray = label.encodeToByteArray()

            require(byteCache.size <= MAX_LABEL_LENGTH_IN_OCTETS) { label }
            return DnsLabel(label)
        }


        fun isReservedLdhLabel(label: String): Boolean {
            if (!isLdhLabel(label)) {
                return false
            }
            return isReservedLdhLabelInternal(label)
        }

        fun isReservedLdhLabelInternal(label: String): Boolean {
            return label.length >= 4 && label[2] == '-' && label[3] == '-'
        }


        private fun from(label: String): DnsLabel {
            require(!(label.isEmpty())) { "Label is null or empty" }

            if (isLdhLabel(label)) {
                return fromLdhLabel(label)
            }

            return fromNonLdhLabel(label)
        }


        fun isLdhLabel(label: String): Boolean {
            if (label.isEmpty()) {
                return false
            }

            if (isLeadingOrTrailingLabelInternal(label)) {
                return false
            }

            return consistsOnlyOfLettersDigitsAndHypen(label)
        }

        fun fromLdhLabel(label: String): DnsLabel {
            require(isLdhLabel(label))

            if (isReservedLdhLabel(label)) {
                // Label starts with '??--'. Now let us see if it is a XN-Label, starting with 'xn--', but be aware that the
                // 'xn' part is case insensitive. The XnLabel.isXnLabelInternal(String) method takes care of this.
                return if (isXnLabelInternal(label)) {
                    fromXnLabel(label)
                } else {
                    create(label)
                }
            }
            return create(label)
        }

        fun fromXnLabel(label: String): DnsLabel {
            require(isIdnAcePrefixed(label))
            return create(label)
        }

        fun isXnLabelInternal(label: String): Boolean {
            // Note that we already ensure the minimum label length here, since reserved LDH
            // labels must start with "xn--".
            return label.substring(0, 2).lowercase() == "xn"
        }

        fun isUnderscoreLabelInternal(label: String): Boolean {
            return label[0] == '_'
        }

        fun fromNonLdhLabel(label: String): DnsLabel {
            if (isUnderscoreLabelInternal(label)) {
                return create(label)
            }

            isLeadingOrTrailingLabelInternal(label)

            return create(label)
        }


        fun from(labels: List<String>): MutableList<DnsLabel> {
            val res: MutableList<DnsLabel> = mutableListOf()

            for (i in labels.indices) {
                res.add(from(labels[i]))
            }

            return res
        }

        private fun isIdnAcePrefixed(string: String): Boolean {
            return string.lowercase().startsWith("xn--")
        }

        private fun toSafeRepresentation(dnsLabel: String): String {
            if (consistsOnlyOfLettersDigitsHypenAndUnderscore(dnsLabel)) {
                // This label is safe, nothing to do.
                return dnsLabel
            }

            val sb = StringBuilder(2 * dnsLabel.length)
            for (i in 0..dnsLabel.length) {
                val c: Char = dnsLabel[i]
                if (isLdhOrMaybeUnderscore(c, true)) {
                    sb.append(c)
                    continue
                }


                // Let's see if we found and unsafe char we want to replace.
                when (c) {
                    '.' -> sb.append('●')
                    '\\' -> sb.append('⧷')
                    '\u007f' ->  // Convert DEL to U+2421 SYMBOL FOR DELETE
                        sb.append('␡')

                    ' ' -> sb.append('␣')
                    else -> {
                        if (c.code < 32) {
                            // First convert the ASCI control codes to the Unicode Control Pictures
                            val substituteAsInt = c.code + '␀'.code
                            val substitute = substituteAsInt.toChar()
                            sb.append(substitute)
                        } else if (c.code < 127) {
                            // Everything smaller than 127 is now safe to directly append.
                            sb.append(c)
                        } else require(c.code <= 255) {
                            ("The string '" + dnsLabel
                                    + "' contains characters outside the 8-bit range: " + c + " at position " + i)
                        }

                        // Everything that did not match the previous conditions is explicitly escaped.
                        sb.append("〚") // U+301A
                        // Transform the char to hex notation. Note that we have ensure that c is <= 255
                        // here, hence only two hexadecimal places are ok.
                        val hex = c.code.toHexString()
                        sb.append(hex)
                        sb.append("〛") // U+301B
                    }
                }
            }

            return sb.toString()
        }

        private fun isLdhOrMaybeUnderscore(c: Char, underscore: Boolean): Boolean {
            return (c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || (underscore && c == '_')
        }

        private fun consistsOnlyOfLdhAndMaybeUnderscore(
            string: String,
            underscore: Boolean
        ): Boolean {
            for (i in 0..<string.length) {
                val c: Char = string[i]
                if (isLdhOrMaybeUnderscore(c, underscore)) {
                    continue
                }
                return false
            }
            return true
        }

        private fun consistsOnlyOfLettersDigitsAndHypen(string: String): Boolean {
            return consistsOnlyOfLdhAndMaybeUnderscore(string, false)
        }

        private fun consistsOnlyOfLettersDigitsHypenAndUnderscore(string: String): Boolean {
            return consistsOnlyOfLdhAndMaybeUnderscore(string, true)
        }

        fun isLeadingOrTrailingLabelInternal(label: String): Boolean {
            if (label.isEmpty()) {
                return false
            }

            if (label[0] == '-') {
                return true
            }

            return label[label.length - 1] == '-'
        }
    }
}
