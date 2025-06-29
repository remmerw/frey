package io.github.remmerw.frey;


import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;

/**
 * A DNS name, also called "domain name". A DNS name consists of multiple 'labels' (see {@link DnsLabel}) and is subject to certain restrictions (see
 * for example <a href="https://tools.ietf.org/html/rfc3696#section-2">RFC 3696 § 2.</a>).
 * <p>
 * Instances of this class can be created by using {@link #from(String)}.
 * </p>
 * <p>
 * This class holds three representations of a DNS name: ACE, raw ACE and IDN. ACE (ASCII Compatible Encoding), which
 * can be accessed via {@link #ace}, represents mostly the data that got send over the wire. But since DNS names are
 * case insensitive, the ACE value is normalized to lower case. You can use {@link #getRawAce()} to get the raw ACE data
 * that was received, which possibly includes upper case characters. The IDN (Internationalized Domain Name), that is
 * the DNS name as it should be shown to the user, can be retrieved using .
 * </p>
 * More information about Internationalized Domain Names can be found at:
 * <ul>
 * <li><a href="https://unicode.org/reports/tr46/">UTS #46 - Unicode IDNA Compatibility Processing</a>
 * <li><a href="https://tools.ietf.org/html/rfc8753">RFC 8753 - Internationalized Domain Names for Applications (IDNA) Review for New Unicode Versions</a>
 * </ul>
 *
 * @author Florian Schmaus
 * @see <a href="https://tools.ietf.org/html/rfc3696">RFC 3696</a>
 * @see DnsLabel
 */
public record DnsName(String ace, String rawAce, DnsLabel[] labels,
                      DnsLabel[] rawLabels) implements Comparable<DnsName> {

    private static final DnsLabel[] DNS_LABELS_EMPTY = new DnsLabel[0];
    private static final int MAX_LABELS = 128;
    /**
     * @see <a href="https://www.ietf.org/rfc/rfc3490.txt">RFC 3490 § 3.1 1.</a>
     */
    private static final String LABEL_SEP_REGEX = "[.。．｡]";
    private static DnsName ROOT = null;


    private static DnsName create(String name, boolean inAce) {
        String rawAce;
        if (name.isEmpty()) {
            rawAce = root().rawAce;
        } else {
            final int nameLength = name.length();
            final int nameLastPos = nameLength - 1;

            // Strip potential trailing dot. N.B. that we require nameLength > 2, because we don't want to strip the one
            // character string containing only a single dot to the empty string.
            if (nameLength >= 2 && name.charAt(nameLastPos) == '.') {
                name = name.subSequence(0, nameLastPos).toString();
            }

            if (inAce) {
                // Name is already in ACE format.
                rawAce = name;
            } else {
                rawAce = DnsUtility.toASCII(name);
            }
        }

        String ace = rawAce.toLowerCase(Locale.US);

        DnsLabel[] rawLabels;
        DnsLabel[] labels;
        if (isRootLabel(ace)) {
            rawLabels = labels = DNS_LABELS_EMPTY;
        } else {
            labels = getLabels(ace);
            rawLabels = getLabels(rawAce);
        }

        return new DnsName(ace, rawAce, labels, rawLabels);
    }

    private static DnsName create(DnsLabel[] rawLabels) {


        DnsLabel[] labels = new DnsLabel[rawLabels.length];

        int size = 0;
        for (int i = 0; i < rawLabels.length; i++) {
            size += rawLabels[i].length() + 1;
            labels[i] = rawLabels[i].asLowercaseVariant();
        }

        String rawAce = labelsToString(rawLabels, size);
        String ace = labelsToString(labels, size);

        return new DnsName(ace, rawAce, labels, rawLabels);
    }

    public static DnsName root() {
        if (ROOT == null) {
            ROOT = DnsName.create(".", true);
        }
        return ROOT;
    }

    private static String labelsToString(DnsLabel[] labels, int stringLength) {
        StringBuilder sb = new StringBuilder(stringLength);
        for (int i = labels.length - 1; i >= 0; i--) {
            sb.append(labels[i]).append('.');
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private static DnsLabel[] getLabels(String ace) {
        String[] labels = ace.split(LABEL_SEP_REGEX, MAX_LABELS);

        // Reverse the labels, so that 'foo, example, org' becomes 'org, example, foo'.
        for (int i = 0; i < labels.length / 2; i++) {
            String t = labels[i];
            int j = labels.length - i - 1;
            labels[i] = labels[j];
            labels[j] = t;
        }
        return DnsLabel.from(labels);
    }

    public static DnsName from(CharSequence name) {
        return from(name.toString());
    }

    private static DnsName from(String name) {
        return DnsName.create(name, false);
    }

    /**
     * Create a DNS name by "concatenating" the child under the parent name. The child can also be seen as the "left"
     * part of the resulting DNS name and the parent is the "right" part.
     * <p>
     * For example using "i.am.the.child" as child and "of.this.parent.example" as parent, will result in a DNS name:
     * "i.am.the.child.of.this.parent.example".
     * </p>
     *
     * @param child  the child DNS name.
     * @param parent the parent DNS name.
     * @return the resulting of DNS name.
     */
    private static DnsName from(DnsName child, DnsName parent) {
        DnsLabel[] rawLabels = new DnsLabel[child.rawLabels.length + parent.rawLabels.length];
        System.arraycopy(parent.rawLabels, 0, rawLabels, 0, parent.rawLabels.length);
        System.arraycopy(child.rawLabels, 0, rawLabels, parent.rawLabels.length, child.rawLabels.length);
        return DnsName.create(rawLabels);
    }

    /**
     * Parse a domain name starting at the current offset and moving the input
     * stream pointer past this domain name (even if cross references occure).
     *
     * @param dis  The input stream.
     * @param data The raw data (for cross references).
     * @return The domain name string.
     * @throws IOException Should never happen.
     */
    public static DnsName parse(DataInputStream dis, byte[] data)
            throws IOException {
        int c = dis.readUnsignedByte();
        if ((c & 0xc0) == 0xc0) {
            c = ((c & 0x3f) << 8) + dis.readUnsignedByte();
            HashSet<Integer> jumps = new HashSet<>();
            jumps.add(c);
            return parse(data, c, jumps);
        }
        if (c == 0) {
            return root();
        }
        byte[] b = new byte[c];
        dis.readFully(b);

        String childLabelString = new String(b, StandardCharsets.US_ASCII);
        DnsName child = DnsName.create(childLabelString, true);

        DnsName parent = parse(dis, data);
        return DnsName.from(child, parent);
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
    private static DnsName parse(byte[] data, int offset, HashSet<Integer> jumps)
            throws IllegalStateException {
        int c = data[offset] & 0xff;
        if ((c & 0xc0) == 0xc0) {
            c = ((c & 0x3f) << 8) + (data[offset + 1] & 0xff);
            if (jumps.contains(c)) {
                throw new IllegalStateException("Cyclic offsets detected.");
            }
            jumps.add(c);
            return parse(data, c, jumps);
        }
        if (c == 0) {
            return root();
        }

        String childLabelString = new String(data, offset + 1, c, StandardCharsets.US_ASCII);
        DnsName child = DnsName.create(childLabelString, true);

        DnsName parent = parse(data, offset + 1 + c, jumps);
        return DnsName.from(child, parent);
    }

    private static boolean isRootLabel(String ace) {
        return ace.isEmpty() || ace.equals(".");
    }

    public String ace() {
        return ace;
    }


    public void writeToStream(OutputStream os) throws IOException {

        for (int i = labels.length - 1; i >= 0; i--) {
            labels[i].writeToStream(os);
        }
        os.write(0);
    }


    /**
     * Returns the raw ACE version of this DNS name. That is, the version as it was
     * received over the wire. Most notably, this version may include uppercase
     * letters.
     * <p>
     * <b>Please refer  for a discussion of the security
     * implications when working with the ACE representation of a DNS name.</b>
     *
     * @return the raw ACE version of this DNS name.
     */
    public String getRawAce() {
        return rawAce;
    }

    public int size() {
        if (isRootLabel(ace)) {
            return 1;
        } else {
            return ace.length() + 2;
        }

    }

    @Override
    public String toString() {

        if (labels.length == 0) {
            return ".";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = labels.length - 1; i >= 0; i--) {
            // Note that it is important that we append the result of DnsLabel.toString() to
            // the StringBuilder. As only the result of toString() is the safe label
            // representation.
            String safeLabelRepresentation = labels[i].toString();
            sb.append(safeLabelRepresentation);
            if (i != 0) {
                sb.append('.');
            }
        }
        return sb.toString();

    }

    @Override
    public int compareTo(DnsName other) {
        return ace.compareTo(other.ace);
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (other instanceof DnsName otherDnsName) {
            return Arrays.equals(labels, otherDnsName.labels);
        }
        return false;
    }

}
