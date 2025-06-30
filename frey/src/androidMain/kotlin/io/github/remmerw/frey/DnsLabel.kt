package io.github.remmerw.frey;


import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A DNS label is an individual component of a DNS name. Labels are usually shown separated by dots.
 * <p>
 * This class implements {@link Comparable} which compares DNS labels according to the Canonical DNS Name Order as
 * specified in <a href="https://tools.ietf.org/html/rfc4034#section-6.1">RFC 4034 § 6.1</a>.
 * </p>
 * <p>
 * Note that as per <a href="https://tools.ietf.org/html/rfc2181#section-11">RFC 2181 § 11</a> DNS labels may contain
 * any byte.
 * </p>
 *
 * @author Florian Schmaus
 * @see <a href="https://tools.ietf.org/html/rfc5890#section-2.2">RFC 5890 § 2.2. DNS-Related Terminology</a>
 */
public record DnsLabel(String label) implements Comparable<DnsLabel> {

    /**
     * The maximum length of a DNS label in octets.
     *
     * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035 § 2.3.4.</a>
     */
    static final int MAX_LABEL_LENGTH_IN_OCTETS = 63;


    static DnsLabel create(String label) {
        byte[] byteCache = label.getBytes(StandardCharsets.US_ASCII);

        if (byteCache.length > MAX_LABEL_LENGTH_IN_OCTETS) {
            throw new IllegalArgumentException(label);
        }
        return new DnsLabel(label);
    }


    static boolean isReservedLdhLabel(String label) {
        if (!isLdhLabel(label)) {
            return false;
        }
        return isReservedLdhLabelInternal(label);
    }

    static boolean isReservedLdhLabelInternal(String label) {
        return label.length() >= 4
                && label.charAt(2) == '-'
                && label.charAt(3) == '-';
    }


    private static DnsLabel from(String label) {
        if (label == null || label.isEmpty()) {
            throw new IllegalArgumentException("Label is null or empty");
        }

        if (isLdhLabel(label)) {
            return fromLdhLabel(label);
        }

        return fromNonLdhLabel(label);
    }


    static boolean isLdhLabel(String label) {
        if (label.isEmpty()) {
            return false;
        }

        if (isLeadingOrTrailingHypenLabelInternal(label)) {
            return false;
        }

        return consistsOnlyOfLettersDigitsAndHypen(label);
    }

    static DnsLabel fromLdhLabel(String label) {
        assert isLdhLabel(label);

        if (isReservedLdhLabel(label)) {
            // Label starts with '??--'. Now let us see if it is a XN-Label, starting with 'xn--', but be aware that the
            // 'xn' part is case insensitive. The XnLabel.isXnLabelInternal(String) method takes care of this.
            if (isXnLabelInternal(label)) {
                return fromXnLabel(label);
            } else {
                return DnsLabel.create(label);
            }
        }
        return DnsLabel.create(label);
    }

    static DnsLabel fromXnLabel(String label) {
        assert isIdnAcePrefixed(label);
        return DnsLabel.create(label);
    }

    static boolean isXnLabelInternal(String label) {
        // Note that we already ensure the minimum label length here, since reserved LDH
        // labels must start with "xn--".
        return label.substring(0, 2).toLowerCase(Locale.US).equals("xn");
    }

    static boolean isUnderscoreLabelInternal(String label) {
        return label.charAt(0) == '_';
    }

    static DnsLabel fromNonLdhLabel(String label) {
        if (isUnderscoreLabelInternal(label)) {
            return DnsLabel.create(label);
        }

        isLeadingOrTrailingHypenLabelInternal(label);

        return DnsLabel.create(label);
    }


    public static List<DnsLabel> from(String[] labels) {
        List<DnsLabel> res = new ArrayList<>();

        for (int i = 0; i < labels.length; i++) {
            res.add(DnsLabel.from(labels[i]));
        }

        return res;
    }

    private static boolean isIdnAcePrefixed(String string) {
        return string.toLowerCase(Locale.US).startsWith("xn--");
    }

    private static String toSafeRepesentation(String dnsLabel) {
        if (consistsOnlyOfLettersDigitsHypenAndUnderscore(dnsLabel)) {
            // This label is safe, nothing to do.
            return dnsLabel;
        }

        StringBuilder sb = new StringBuilder(2 * dnsLabel.length());
        for (int i = 0; i < dnsLabel.length(); i++) {
            char c = dnsLabel.charAt(i);
            if (isLdhOrMaybeUnderscore(c, true)) {
                sb.append(c);
                continue;
            }


            // Let's see if we found and unsafe char we want to replace.
            switch (c) {
                case '.' -> sb.append('●'); // U+25CF BLACK CIRCLE;
                case '\\' -> sb.append('⧷'); // U+29F7 REVERSE SOLIDUS WITH HORIZONTAL STROKE
                case '\u007f' ->
                    // Convert DEL to U+2421 SYMBOL FOR DELETE
                        sb.append('␡');
                case ' ' -> sb.append('␣'); // U+2423 OPEN BOX
                default -> {
                    if (c < 32) {
                        // First convert the ASCI control codes to the Unicode Control Pictures
                        int substituteAsInt = c + '␀';
                        char substitute = (char) substituteAsInt;
                        sb.append(substitute);
                    } else if (c < 127) {
                        // Everything smaller than 127 is now safe to directly append.
                        sb.append(c);
                    } else if (c > 255) {
                        throw new IllegalArgumentException("The string '" + dnsLabel
                                + "' contains characters outside the 8-bit range: " + c + " at position " + i);
                    } else {
                        // Everything that did not match the previous conditions is explicitly escaped.
                        sb.append("〚"); // U+301A
                        // Transform the char to hex notation. Note that we have ensure that c is <= 255
                        // here, hence only two hexadecimal places are ok.
                        String hex = String.format("%02X", (int) c);
                        sb.append(hex);
                        sb.append("〛"); // U+301B
                    }
                }
            }
        }

        return sb.toString();
    }

    private static boolean isLdhOrMaybeUnderscore(char c, boolean underscore) {
        return (c >= 'a' && c <= 'z')
                || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9')
                || c == '-'
                || (underscore && c == '_')
                ;
    }

    private static boolean consistsOnlyOfLdhAndMaybeUnderscore(String string, boolean underscore) {
        for (int i = 0; i < string.length(); i++) {
            char c = string.charAt(i);
            if (isLdhOrMaybeUnderscore(c, underscore)) {
                continue;
            }
            return false;
        }
        return true;
    }

    private static boolean consistsOnlyOfLettersDigitsAndHypen(String string) {
        return consistsOnlyOfLdhAndMaybeUnderscore(string, false);
    }

    private static boolean consistsOnlyOfLettersDigitsHypenAndUnderscore(String string) {
        return consistsOnlyOfLdhAndMaybeUnderscore(string, true);
    }

    static boolean isLeadingOrTrailingHypenLabelInternal(String label) {
        if (label.isEmpty()) {
            return false;
        }

        if (label.charAt(0) == '-') {
            return true;
        }

        return label.charAt(label.length() - 1) == '-';
    }

    public int length() {
        return toSafeString().length();
    }

    private String toSafeString() {
        // The default implementation assumes that toString() returns a safe
        // representation. Subclasses may override toSafeString() if this assumption is
        // not correct.
        return toString();
    }


    @Override
    public String toString() {
        return toSafeRepesentation(label);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof DnsLabel(String label1))) {
            return false;
        }
        return label.equals(label1);
    }

    DnsLabel asLowercaseVariant() {
        String lowercaseLabel = label.toLowerCase(Locale.US);
        return DnsLabel.from(lowercaseLabel);
    }

    void writeToStream(OutputStream os) throws IOException {
        byte[] byteCache = label.getBytes(StandardCharsets.US_ASCII);
        os.write(byteCache.length);
        os.write(byteCache, 0, byteCache.length);
    }

    @Override
    public int compareTo(DnsLabel other) {
        String myCanonical = asLowercaseVariant().label;
        String otherCanonical = other.asLowercaseVariant().label;

        return myCanonical.compareTo(otherCanonical);
    }

}
