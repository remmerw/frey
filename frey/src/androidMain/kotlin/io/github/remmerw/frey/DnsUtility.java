package io.github.remmerw.frey;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;

public interface DnsUtility {


    int UDP_PAYLOAD_SIZE = 1024;
    /**
     * DNS timeout.
     */
    int DNS_TIMEOUT = 5000; // 5000 ms


    static DnsQueryResult query(DnsMessage message, InetAddress address) throws IOException {


        try {
            return new DnsQueryResult(queryUdp(message, address));
        } catch (IOException ignore) {
            // ignore the first query
        }

        return new DnsQueryResult(queryTcp(message, address));

    }

    private static DnsMessage queryUdp(DnsMessage query, InetAddress address) throws IOException {
        DatagramPacket packet = query.asDatagram(address);
        byte[] buffer = new byte[UDP_PAYLOAD_SIZE];
        try (DatagramSocket socket = createDatagramSocket()) {
            socket.setSoTimeout(DNS_TIMEOUT);
            socket.send(packet);
            packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            DnsMessage dnsMessage = DnsMessage.parse(packet.getData());
            if (dnsMessage.id() != query.id()) {
                throw new IllegalStateException("The response's ID doesn't matches the request ID");
            }
            return dnsMessage;
        }
    }

    private static DnsMessage queryTcp(DnsMessage message, InetAddress address) throws IOException {
        try (Socket socket = createSocket()) {
            SocketAddress socketAddress = new InetSocketAddress(address, 53);
            socket.connect(socketAddress, DNS_TIMEOUT);
            socket.setSoTimeout(DNS_TIMEOUT);
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
            message.writeTo(dos);
            dos.flush();
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            int length = dis.readUnsignedShort();
            byte[] data = new byte[length];
            int read = 0;
            while (read < length) {
                read += dis.read(data, read, length - read);
            }
            DnsMessage dnsMessage = DnsMessage.parse(data);
            if (dnsMessage.id() != message.id()) {
                throw new IllegalStateException("The response's ID doesn't matches the request ID");
            }
            return dnsMessage;
        }
    }

    /**
     * Create a {@link Socket} using the system default {@link javax.net.SocketFactory}.
     *
     * @return The new {@link Socket} instance
     */
    private static Socket createSocket() {
        return new Socket();
    }

    /**
     * Create a {@link DatagramSocket} using the system defaults.
     *
     * @return The new {@link DatagramSocket} instance
     * @throws SocketException If creation of the {@link DatagramSocket} fails
     */
    private static DatagramSocket createDatagramSocket() throws SocketException {
        return new DatagramSocket();
    }

    static String toASCII(String input) {
        // Special case if input is ".", i.e. a string containing only a single dot character. This is a workaround for
        // IDN.toASCII() implementations throwing an IllegalArgumentException on this input string (for example Android
        // APIs level 26, see https://issuetracker.google.com/issues/113070416).
        if (DnsName.root().ace().equals(input)) {
            return DnsName.root().ace();
        }

        return IDN.toASCII(input);
    }

    /**
     * @noinspection SameParameterValue
     */
    static Inet4Address ipv4From(CharSequence cs) {
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(cs.toString());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
        if (inetAddress instanceof Inet4Address) {
            return (Inet4Address) inetAddress;
        }
        throw new IllegalArgumentException();
    }

    /**
     * @noinspection SameParameterValue
     */
    static Inet6Address ipv6From(CharSequence cs) {
        InetAddress inetAddress;
        try {
            inetAddress = InetAddress.getByName(cs.toString());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
        if (inetAddress instanceof Inet6Address) {
            return (Inet6Address) inetAddress;
        }
        throw new IllegalArgumentException();
    }
}
