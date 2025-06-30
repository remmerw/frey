package io.github.remmerw.frey

import io.github.remmerw.frey.DnsName.Companion.root
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.IDN
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.SocketException
import java.net.UnknownHostException

interface DnsUtility {
    companion object {
        @Throws(IOException::class)
        fun query(message: DnsMessage, address: InetAddress?): DnsQueryResult {
            try {
                return DnsQueryResult(queryUdp(message, address))
            } catch (ignore: IOException) {
                // ignore the first query
            }

            return DnsQueryResult(queryTcp(message, address))
        }

        @Throws(IOException::class)
        private fun queryUdp(query: DnsMessage, address: InetAddress?): DnsMessage {
            var packet = query.asDatagram(address)
            val buffer = ByteArray(UDP_PAYLOAD_SIZE)
            createDatagramSocket().use { socket ->
                socket.setSoTimeout(DNS_TIMEOUT)
                socket.send(packet)
                packet = DatagramPacket(buffer, buffer.size)
                socket.receive(packet)
                val dnsMessage: DnsMessage = DnsMessage.Companion.parse(packet.data)
                check(dnsMessage.id == query.id) { "The response's ID doesn't matches the request ID" }
                return dnsMessage
            }
        }

        @Throws(IOException::class)
        private fun queryTcp(message: DnsMessage, address: InetAddress?): DnsMessage {
            createSocket().use { socket ->
                val socketAddress: SocketAddress = InetSocketAddress(address, 53)
                socket.connect(socketAddress, DNS_TIMEOUT)
                socket.setSoTimeout(DNS_TIMEOUT)
                val dos = DataOutputStream(socket.getOutputStream())
                message.writeTo(dos)
                dos.flush()
                val dis = DataInputStream(socket.getInputStream())
                val length = dis.readUnsignedShort()
                val data = ByteArray(length)
                var read = 0
                while (read < length) {
                    read += dis.read(data, read, length - read)
                }
                val dnsMessage: DnsMessage = DnsMessage.Companion.parse(data)
                check(dnsMessage.id == message.id) { "The response's ID doesn't matches the request ID" }
                return dnsMessage
            }
        }

        /**
         * Create a [Socket] using the system default [javax.net.SocketFactory].
         *
         * @return The new [Socket] instance
         */
        private fun createSocket(): Socket {
            return Socket()
        }

        /**
         * Create a [DatagramSocket] using the system defaults.
         *
         * @return The new [DatagramSocket] instance
         * @throws SocketException If creation of the [DatagramSocket] fails
         */
        @Throws(SocketException::class)
        private fun createDatagramSocket(): DatagramSocket {
            return DatagramSocket()
        }

        fun toASCII(input: String): String {
            // Special case if input is ".", i.e. a string containing only a single dot character. This is a workaround for
            // IDN.toASCII() implementations throwing an IllegalArgumentException on this input string (for example Android
            // APIs level 26, see https://issuetracker.google.com/issues/113070416).
            if (root().ace == input) {
                return root().ace
            }

            return IDN.toASCII(input)
        }

        /**
         * @noinspection SameParameterValue
         */
        fun ipv4From(cs: CharSequence): Inet4Address {
            val inetAddress: InetAddress?
            try {
                inetAddress = InetAddress.getByName(cs.toString())
            } catch (e: UnknownHostException) {
                throw IllegalArgumentException(e)
            }
            if (inetAddress is Inet4Address) {
                return inetAddress
            }
            throw IllegalArgumentException()
        }

        /**
         * @noinspection SameParameterValue
         */
        fun ipv6From(cs: CharSequence): Inet6Address {
            val inetAddress: InetAddress?
            try {
                inetAddress = InetAddress.getByName(cs.toString())
            } catch (e: UnknownHostException) {
                throw IllegalArgumentException(e)
            }
            if (inetAddress is Inet6Address) {
                return inetAddress
            }
            throw IllegalArgumentException()
        }

        const val UDP_PAYLOAD_SIZE: Int = 1024

        /**
         * DNS timeout.
         */
        const val DNS_TIMEOUT: Int = 5000 // 5000 ms
    }
}
