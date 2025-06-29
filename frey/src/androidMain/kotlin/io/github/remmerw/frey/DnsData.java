package io.github.remmerw.frey;


import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Generic payload class.
 */
public interface DnsData {

    byte[] bytes();


    default int length() {
        return bytes().length;
    }

    /**
     * Write the binary representation of this payload to the given {@link DataOutputStream}.
     *
     * @param dos the DataOutputStream to write to.
     * @throws IOException if an I/O error occurs.
     */
    default void toOutputStream(DataOutputStream dos) throws IOException {
        dos.write(bytes());
    }

    /**
     * OPT payload (see RFC 2671 for details).
     */
    record OPT(DnsEdns.Option[] variablePart) implements DnsData {

        public static OPT parse(DataInputStream dis, int payloadLength) throws IOException {
            List<DnsEdns.Option> variablePart;
            if (payloadLength == 0) {
                variablePart = Collections.emptyList();
            } else {
                int payloadLeft = payloadLength;
                variablePart = new ArrayList<>(4);
                while (payloadLeft > 0) {
                    int optionCode = dis.readUnsignedShort();
                    int optionLength = dis.readUnsignedShort();
                    byte[] optionData = new byte[optionLength];
                    //noinspection ResultOfMethodCallIgnored
                    dis.read(optionData);
                    DnsEdns.Option option = DnsEdns.Option.parse(optionCode, optionData);
                    variablePart.add(option);
                    payloadLeft -= 2 + 2 + optionLength;
                    // Assert that payloadLeft never becomes negative
                    assert payloadLeft >= 0;
                }
            }
            DnsEdns.Option[] parts = new DnsEdns.Option[variablePart.size()];
            return new OPT(variablePart.toArray(parts));
        }


        @Override
        public byte[] bytes() {

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            try {
                for (DnsEdns.Option endsOption : variablePart) {
                    endsOption.writeToDos(dos);
                }
            } catch (IOException e) {
                // Should never happen.
                throw new AssertionError(e);
            }
            return baos.toByteArray();
        }
    }

    /**
     * A TXT record. Actually a binary blob containing extents, each of which is a one-byte count
     * followed by that many bytes of data, which can usually be interpreted as ASCII strings
     * but not always.
     */
    record TXT(byte[] blob) implements DnsData {

        public static TXT parse(DataInputStream dis, int length) throws IOException {
            byte[] blob = new byte[length];
            dis.readFully(blob);
            return new TXT(blob);
        }

        public String getText() {
            StringBuilder sb = new StringBuilder();
            Iterator<String> it = getCharacterStrings().iterator();
            while (it.hasNext()) {
                sb.append(it.next());
                if (it.hasNext()) {
                    sb.append(" / ");
                }
            }
            return sb.toString();
        }

        private List<String> getCharacterStrings() {
            List<byte[]> extents = getExtents();
            List<String> characterStrings = new ArrayList<>(extents.size());
            for (byte[] extent : extents) {
                characterStrings.add(new String(extent, StandardCharsets.UTF_8));
            }
            return Collections.unmodifiableList(characterStrings);
        }

        private List<byte[]> getExtents() {
            ArrayList<byte[]> extents = new ArrayList<>();
            int segLength;
            for (int used = 0; used < blob.length; used += segLength) {
                segLength = 0x00ff & blob[used];
                int end = ++used + segLength;
                byte[] extent = Arrays.copyOfRange(blob, used, end);
                extents.add(extent);
            }
            return extents;
        }


        @Override
        public String toString() {
            return "\"" + getText() + "\"";
        }

        @Override
        public byte[] bytes() {
            return blob;
        }

    }


    record UNKNOWN(byte[] data) implements DnsData {


        private static UNKNOWN create(DataInputStream dis, int payloadLength) throws IOException {
            byte[] data = new byte[payloadLength];
            dis.readFully(data);
            return new UNKNOWN(data);
        }

        public static UNKNOWN parse(DataInputStream dis, int payloadLength)
                throws IOException {
            return UNKNOWN.create(dis, payloadLength);
        }


        @Override
        public byte[] bytes() {
            return data;
        }

    }
}
